// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION ON THE DOOR PATH (ARCHITECT RULING 2026-10-03, Q-FOLD-A2A-2-PROJECT-POOL session
//! half): the door's `project`, entered as the dispatcher enters it and checked as the loader checks
//! every answer, writes the caller's `contextId` into the hook view's opaque session.

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::{ProjectIn, ProjectOut};
use busbar_contract::abi::sdk::Safe;
use busbar_plane_a2a::door;
use busbar_plane_a2a::plane_door::Project;
use serde_json::json;

/// One `project` of `body` arriving on claim `claim` at `target`, through the door's own entry,
/// checked as the loader checks every answer (`check_project`): the outcome and the session the
/// view names, as text (`None` = absent).
fn project_session(claim: usize, target: &str, body: &[u8]) -> (Outcome, Option<String>) {
    use busbar_contract::abi::hook::SignalEntry;
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_OCTETS};
    use busbar_contract::abi::sdk::door::{blank_in, blank_out, Entry};
    let mut signals = [SignalEntry {
        id: 0,
        tag: 0,
        value: busbar_contract::abi::hook::SignalValue { u64_: 0 },
    }; 4];
    let mut arena = vec![0u8; 4096];
    let input = ProjectIn {
        claim: u32::try_from(claim).unwrap(),
        target: AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        },
        body: Blob {
            ptr: body.as_ptr(),
            len: body.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        },
        signals_buf: signals.as_mut_ptr(),
        signals_cap: signals.len(),
        arena_buf: arena.as_mut_ptr(),
        arena_cap: arena.len(),
        ..blank_in()
    };
    let mut out: ProjectOut = blank_out();
    // SAFETY: `input`'s pointers name the live buffers above for the call; the door's `project`
    // reads no instance.
    let outcome = unsafe {
        <Safe<Project> as Entry>::enter(
            std::ptr::null_mut(),
            busbar_contract::abi::plane::slot::PROJECT,
            &input,
            &mut out,
        )
    };
    busbar_contract::abi::plane::check::check_project(
        outcome,
        &out,
        &signals,
        signals.len() as u64,
        (arena.as_ptr(), arena.len() as u64),
    )
    .expect("the answer passes the loader's check");
    let s = out.view.session;
    let session = (!s.ptr.is_null()).then(|| {
        assert_eq!(s.fmt, BLOB_OCTETS);
        let at = s.ptr as usize - arena.as_ptr() as usize;
        String::from_utf8(arena[at..at + s.len].to_vec()).unwrap()
    });
    (outcome, session)
}

/// The claim the door states for `verb target`.
fn claim_of(verb: &str, target: &str) -> usize {
    door::ROUTES
        .iter()
        .position(|r| r.verb == verb && r.target == target)
        .expect("a stated route")
}

/// THE SESSION ON THE DOOR PATH (ARCHITECT RULING 2026-10-03, Q-FOLD-A2A-2-PROJECT-POOL session
/// half): `project` writes the `contextId` the caller's message names into the hook view's opaque
/// session, on the JSON-RPC line and the HTTP+JSON line alike; a message that names none leaves it
/// absent, so the request is screened whole.
#[test]
fn project_writes_the_messages_context_id_as_the_session() {
    let document = claim_of("POST", "/a2a/agents/{agent_id}");
    let send = |context: Option<&str>| {
        let mut message = json!({ "role": "user", "messageId": "m1", "parts": [{ "text": "hi" }] });
        if let Some(c) = context {
            message["contextId"] = json!(c);
        }
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": { "message": message },
        }))
        .unwrap()
    };
    assert_eq!(
        project_session(document, "/a2a/agents/planner", &send(Some("ctx-7"))),
        (Outcome::Ready, Some("ctx-7".to_string()))
    );
    assert_eq!(
        project_session(document, "/a2a/agents/planner", &send(None)),
        (Outcome::Ready, None)
    );
    assert_eq!(
        project_session(document, "/a2a/agents/planner", &send(Some(""))),
        (Outcome::Ready, None),
        "an empty contextId is no session"
    );

    let target = claim_of("POST", "/a2a/message:send");
    let rest = serde_json::to_vec(&json!({
        "message": {
            "role": "ROLE_USER", "messageId": "m2", "contextId": "ctx-9",
            "parts": [{ "text": "hi" }],
        },
    }))
    .unwrap();
    assert_eq!(
        project_session(target, "/a2a/message:send", &rest),
        (Outcome::Ready, Some("ctx-9".to_string()))
    );
}
