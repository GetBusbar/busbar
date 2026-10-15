//! Tests for `door.rs`: the piece bits the door states for what its framing yields.

use super::*;
use busbar_contract::abi::transport::PIECE_STREAM_FAILED;

fn piece(bytes: &[u8], fields: bool, text: bool, end: bool) -> Piece {
    Piece {
        stream: 1,
        bytes: bytes.to_vec(),
        fields,
        text,
        end,
    }
}

/// A CLOSED DATA CHANNEL ENDS ITS STREAM BY FLAG (the transport contract: "streams end by flag";
/// an empty piece without `PIECE_END` is an empty message). The end is its own empty piece with
/// `PIECE_END` and `PIECE_END_OF_FRAME`, and never text, a field block, a failure or a continuation,
/// which `check_framer` refuses beside an end.
#[test]
fn a_closed_channel_is_the_streams_end_by_flag_never_an_empty_message() {
    let end = piece(b"", false, false, true);
    let flags = piece_flags(&end, false, true, 0);
    assert_eq!(flags, PIECE_END | PIECE_END_OF_FRAME);
    assert_eq!(
        flags & (PIECE_TEXT | PIECE_FIELDS | PIECE_CONTINUED | PIECE_STREAM_FAILED),
        0
    );
    // An empty binary message is a frame, and it does not end the stream.
    let empty = piece(b"", false, false, false);
    assert_eq!(piece_flags(&empty, false, true, 0), PIECE_END_OF_FRAME);
    // An empty text message is a frame too: not text (it carries no bytes), not the end.
    let empty_text = piece(b"", false, true, false);
    assert_eq!(piece_flags(&empty_text, false, true, 0), PIECE_END_OF_FRAME);
}

/// The other pieces keep the bits they had: a message's text, a field block and its continuation,
/// and the frame's end only on the piece that carries its last byte.
#[test]
fn messages_and_field_blocks_keep_their_bits() {
    let text = piece(b"{\"type\":\"hello\"}", false, true, false);
    assert_eq!(
        piece_flags(&text, false, true, text.bytes.len()),
        PIECE_TEXT | PIECE_END_OF_FRAME
    );
    assert_eq!(piece_flags(&text, false, false, 4), PIECE_TEXT);
    let head = piece(b"label: events\r\n", true, false, false);
    assert_eq!(
        piece_flags(&head, false, true, head.bytes.len()),
        PIECE_FIELDS | PIECE_END_OF_FRAME
    );
    assert_eq!(
        piece_flags(&head, true, true, head.bytes.len()),
        PIECE_FIELDS | PIECE_CONTINUED | PIECE_END_OF_FRAME
    );
}
