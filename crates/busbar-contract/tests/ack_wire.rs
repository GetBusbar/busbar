//! Red-before-green guard for the single `kinds::Ack` export acknowledgement wire (RULING #4).
//!
//! The ONE `Ack` type both faces name must (a) deserialize as well as serialize, and (b) use
//! `snake_case` tokens. Before the fresh cut, `Ack` derived `Serialize` only with no `rename_all`,
//! so it could not be read back off the wire and would have emitted PascalCase (`"Durable"`) against
//! the `durable` the export docs / #2 self-test expect. This test fails on either regression.

use busbar_contract::kinds::Ack;

#[test]
fn ack_wire_tokens_are_snake_case_and_round_trip() {
    for (ack, token) in [
        (Ack::Durable, "\"durable\""),
        (Ack::Received, "\"received\""),
        (Ack::Retry, "\"retry\""),
    ] {
        let json = serde_json::to_string(&ack).expect("Ack serializes");
        assert_eq!(json, token, "snake_case wire token");
        let back: Ack =
            serde_json::from_str(&json).expect("Ack deserializes (single type, both faces)");
        assert_eq!(back, ack, "round-trips byte-identically");
    }
}

#[test]
fn ack_rejects_pascalcase_tokens() {
    // The wire is snake_case: a PascalCase token is not a valid Ack.
    assert!(serde_json::from_str::<Ack>("\"Durable\"").is_err());
}
