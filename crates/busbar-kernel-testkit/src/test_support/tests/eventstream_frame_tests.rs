#[test]
fn eventstream_frame_spells_a_crc_valid_converse_stream_event() {
    let payload = br#"{"stopReason":"end_turn"}"#;
    let mut want: Vec<u8> = vec![0, 0, 0, 0x7a, 0, 0, 0, 0x51, 0xca, 0x2c, 0x46, 0x65];
    want.extend_from_slice(b"\x0b:event-type\x07\x00\x0bmessageStop");
    want.extend_from_slice(b"\x0d:content-type\x07\x00\x10application/json");
    want.extend_from_slice(b"\x0d:message-type\x07\x00\x05event");
    want.extend_from_slice(payload);
    want.extend_from_slice(&[0x5f, 0xbf, 0x09, 0xfc]);
    assert_eq!(super::eventstream_frame("messageStop", payload), want);
}
