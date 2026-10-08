// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A stdio child's messages, read whole and correlated by id (ARCHITECT round 5
//! Q-L3B-STDIO-UPSTREAM (A)).

use super::*;
use serde_json::json;

/// The door, as these tests stand in for it: what it answered, what it was told.
#[derive(Default)]
struct Door {
    claimed: Vec<(u64, String)>,
    noticed: u32,
    grants: ServerRequestGrants,
}

impl Peer for Door {
    fn grants(&self) -> ServerRequestGrants {
        self.grants
    }
    fn claim(&mut self, generation: u64, id: &Value) -> bool {
        let key = (generation, id.to_string());
        if self.claimed.contains(&key) {
            return false;
        }
        self.claimed.push(key);
        true
    }
    fn notice(&mut self) {
        self.noticed += 1;
    }
}

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// RED: the child's frames are read as whole messages however the host's buffer cut them, back to
/// back with no separator, and bytes that are not JSON are handed on as such.
#[test]
fn messages_are_read_whole_across_pieces() {
    let mut f = Frames::default();
    let one = bytes(&json!({"jsonrpc": "2.0", "id": 1, "result": {"a": "x".repeat(40)}}));
    let two = bytes(&json!({"jsonrpc": "2.0", "method": "notifications/message"}));
    let mut all = one.clone();
    all.extend_from_slice(&two);
    let (head, tail) = all.split_at(17);
    assert!(f.push(head).is_empty(), "a message part way through waits");
    let read = f.push(tail);
    assert_eq!(read.len(), 2);
    assert_eq!(
        read[0],
        Message::Value(serde_json::from_slice(&one).unwrap())
    );
    assert_eq!(
        read[1],
        Message::Value(serde_json::from_slice(&two).unwrap())
    );
    assert_eq!(
        f.push(b"oops not json"),
        vec![Message::NotJson(b"oops not json".to_vec())]
    );
}

/// RED: only the response carrying the id this exchange sent is its answer; a response to another
/// id (another exchange's, on the same child) is passed over, wherever it falls.
#[test]
fn the_answer_is_the_response_carrying_this_exchanges_id() {
    let mut c = Correlator::default();
    let mut door = Door::default();
    let other = bytes(&json!({"jsonrpc": "2.0", "id": 7, "result": {"theirs": true}}));
    let ours = bytes(&json!({"jsonrpc": "2.0", "id": 9, "result": {"ours": true}}));
    assert_eq!(c.take(&other, 9, "srv", 1, &mut door), Ok(None));
    let got = c
        .take(&ours, 9, "srv", 1, &mut door)
        .unwrap()
        .expect("our answer");
    assert_eq!(
        serde_json::from_slice::<Value>(&got).unwrap()["result"]["ours"],
        json!(true)
    );
}

/// RED: the child's own messages read while waiting are handled as the previous release handled
/// them on the stdio leg: progress carrying this call's token is kept (another call's is not); a
/// list-changed notification brings verify-on-call forward; a `ping` and an unknown request are
/// answered — ONCE per generation and id, whichever exchange read them first.
#[test]
fn the_childs_own_messages_are_handled_on_the_way() {
    let mut door = Door::default();
    let mut c = Correlator::default();
    let stream = [
        json!({"jsonrpc": "2.0", "method": "notifications/progress",
               "params": {"progressToken": "busbar-9", "progress": 1}}),
        json!({"jsonrpc": "2.0", "method": "notifications/progress",
               "params": {"progressToken": "busbar-7", "progress": 1}}),
        json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
        json!({"jsonrpc": "2.0", "id": "p1", "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "vendor/thing"}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "roots/list"}),
        json!({"jsonrpc": "2.0", "id": 9, "result": {}}),
    ];
    let all: Vec<u8> = stream.iter().flat_map(bytes).collect();
    assert!(c.take(&all, 9, "srv", 1, &mut door).unwrap().is_some());
    assert_eq!(c.progress.len(), 1, "only this call's progress");
    assert_eq!(c.progress[0]["params"]["progressToken"], json!("busbar-9"));
    assert_eq!(door.noticed, 1);
    let replies: Vec<Value> = c
        .outbox
        .iter()
        .map(|r| serde_json::from_slice(r).unwrap())
        .collect();
    assert_eq!(replies.len(), 3);
    assert_eq!(
        replies[0],
        json!({"jsonrpc": "2.0", "id": "p1", "result": {}})
    );
    assert_eq!(replies[1]["error"]["code"], json!(-32601));
    assert_eq!(replies[2]["id"], json!(4));
    assert_eq!(
        replies[2]["error"]["code"],
        json!(-32001),
        "an ungranted ask is refused"
    );
    // Another exchange reading the same requests of the same generation answers none of them.
    let mut again = Correlator::default();
    assert_eq!(again.take(&all, 5, "srv", 1, &mut door), Ok(None));
    assert!(again.outbox.is_empty());
    // The next generation's child is another child: its requests are its own.
    let mut next = Correlator::default();
    next.take(&all, 5, "srv", 2, &mut door).unwrap();
    assert_eq!(next.outbox.len(), 3);
}

/// RED: past the work budget of messages of the child's own, the exchange is abandoned in the
/// previous release's words.
#[test]
fn a_child_that_floods_its_own_messages_abandons_the_exchange() {
    let mut door = Door::default();
    let mut c = Correlator::default();
    let note = bytes(&json!({"jsonrpc": "2.0", "method": "notifications/message"}));
    let flood: Vec<u8> = std::iter::repeat_n(note, MAX_INTERLEAVED_MESSAGES as usize + 1)
        .flatten()
        .collect();
    let refused = c.take(&flood, 9, "srv", 1, &mut door).unwrap_err();
    assert!(
        refused.starts_with("stdio MCP child sent more than 256 messages of its own"),
        "{refused}"
    );
}

/// The ids busbar sends a child never meet: a unit's call ids, its list ids, the handshake's and
/// every dispatch id are disjoint.
#[test]
fn every_id_on_a_child_is_its_own() {
    assert_ne!(call_id(1, 0), call_id(2, 0));
    assert_ne!(call_id(1, 0), call_id(1, 1));
    assert_ne!(call_id(1, 0), list_id(1, 0));
    assert!(call_id(0, 0) > HANDSHAKE_REQUEST_ID);
    assert!(list_id(0, 0) > crate::client::jsonrpc::dispatch_request_id(u32::MAX));
    assert_eq!(generation_of(b"generation: 12\r\n"), 12);
    assert_eq!(generation_of(b"other: 1\r\n"), 0);
}

/// LAW 11 (ARCHITECT Q6), RED against the deleted "no satisfier" reply: a GRANTED authority ask the
/// child sends while busbar relays a call is TAKEN for the caller, verbatim, and busbar writes the
/// child nothing in its place; an UNGRANTED one is still refused on the child's input
/// (`ask_ungranted`); `ping` is still answered by busbar (keepalive, not an ask).
#[test]
fn a_granted_ask_is_taken_for_the_caller_and_never_answered_here() {
    let mut door = Door {
        grants: ServerRequestGrants {
            sampling: true,
            ..ServerRequestGrants::default()
        },
        ..Door::default()
    };
    let sampling = json!({"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage",
                          "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
                                     "maxTokens": 9}});
    let stream = [
        sampling.clone(),
        json!({"jsonrpc": "2.0", "id": 4, "method": "roots/list"}),
        json!({"jsonrpc": "2.0", "id": "p", "method": "ping"}),
    ];
    let all: Vec<u8> = stream.iter().flat_map(bytes).collect();
    let mut c = Correlator::relaying();
    assert_eq!(c.take(&all, 9, "srv", 1, &mut door), Ok(None));
    assert_eq!(c.asks.len(), 1, "the granted ask is the caller's");
    assert_eq!(c.asks[0].id, json!("srv-1"));
    assert_eq!(
        c.asks[0].request,
        json!({"method": "sampling/createMessage", "params": sampling["params"]}),
        "the request as the child sent it, less its envelope"
    );
    let replies: Vec<Value> = c
        .outbox
        .iter()
        .map(|r| serde_json::from_slice(r).unwrap())
        .collect();
    assert_eq!(
        replies.len(),
        2,
        "busbar answered only the ping and the refusal"
    );
    assert!(
        replies.iter().all(|r| r["id"] != json!("srv-1")),
        "busbar wrote nothing for the granted ask: {replies:?}"
    );
    assert_eq!(replies[0]["id"], json!(4));
    assert_eq!(
        replies[0]["error"]["data"]["reason"],
        json!("ask_ungranted")
    );
    assert_eq!(
        replies[1],
        json!({"jsonrpc": "2.0", "id": "p", "result": {}})
    );
}

/// An exchange of the door's own (a greeting, a tool list) relays no call: it neither takes nor
/// answers a granted ask, and leaves it unclaimed for the exchange relaying the call to take.
#[test]
fn an_exchange_of_the_doors_own_leaves_a_granted_ask_for_the_call() {
    let mut door = Door {
        grants: ServerRequestGrants {
            elicitation: true,
            ..ServerRequestGrants::default()
        },
        ..Door::default()
    };
    let ask = bytes(
        &json!({"jsonrpc": "2.0", "id": 5, "method": "elicitation/create",
                            "params": {"message": "ok?"}}),
    );
    let mut own = Correlator::default();
    assert_eq!(own.take(&ask, 1, "srv", 1, &mut door), Ok(None));
    assert!(own.asks.is_empty() && own.outbox.is_empty());
    let mut call = Correlator::relaying();
    assert_eq!(call.take(&ask, 9, "srv", 1, &mut door), Ok(None));
    assert_eq!(call.asks.len(), 1, "the call's exchange takes it");
}

/// The caller is handed the child's requests verbatim, keyed by the child's own ids; its answers go
/// back to the child under those ids, each the caller's answer verbatim.
#[test]
fn the_childs_asks_go_out_verbatim_and_the_answers_come_back_under_its_ids() {
    let asks = vec![
        ChildAsk {
            id: json!("srv-1"),
            request: json!({"method": "elicitation/create", "params": {"message": "ok?"}}),
        },
        ChildAsk {
            id: json!(7),
            request: json!({"method": "roots/list"}),
        },
    ];
    let (result, keys) = relayed_asks(&asks);
    assert_eq!(result["resultType"], json!("input_required"));
    assert_eq!(result["inputRequests"]["srv-1"], asks[0].request);
    assert_eq!(result["inputRequests"]["7"], asks[1].request);
    assert_eq!(
        keys,
        vec![
            ("srv-1".to_string(), json!("srv-1")),
            ("7".to_string(), json!(7))
        ]
    );
    let leg = crate::ask::ChildLeg {
        generation: 1,
        wait: 9,
        asks: keys,
        work: None,
    };
    let answers =
        json!({"srv-1": {"action": "accept", "content": {"ok": true}}, "7": {"roots": []}});
    let replies: Vec<Value> = child_replies(&leg, Some(&answers))
        .iter()
        .map(|r| serde_json::from_slice(r).unwrap())
        .collect();
    assert_eq!(
        replies,
        vec![
            json!({"jsonrpc": "2.0", "id": "srv-1", "result": answers["srv-1"]}),
            json!({"jsonrpc": "2.0", "id": 7, "result": {"roots": []}}),
        ]
    );
}
