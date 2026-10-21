// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONTROL PEER: a strict RFC 6455 echo server on the standard library alone, so the control
//! leg proves the harness grades a correct peer green BEFORE any busbar verdict is believed.
//!
//! INDEPENDENT OF THE SUBJECT. busbar's ws framer is tungstenite's frame codec
//! (`qa/construction.toml`, `busbar-transport-ws`); this peer links no busbar crate and no
//! WebSocket library, so a defect the two share cannot grade itself green. Neither third-party
//! peer tried before was strict: the npm `ws` package is NON-STRICT on 6.4.1-6.4.4 and FAILED on
//! 9.3.x/9.4.x, and Autobahn's own echoserver is NON-STRICT on 3.2, 3.3, 4.1.3, 4.1.4, 4.2.3,
//! 4.2.4 and 5.15. This one is written to the suite's strict grades:
//!
//! * every frame is handled in order, and an echo is written before the next frame is read, so a
//!   good message ahead of a bad frame is answered before the connection fails (3.2, 4.x, 5.15);
//! * text is UTF-8 checked byte by byte AS IT ARRIVES, inside a frame and across fragments, so an
//!   invalid sequence fails the connection before the rest of the message is sent (6.4.x);
//! * a failure sends its close code (1002 protocol, 1007 bad UTF-8), half-closes, and drains, so
//!   nothing it already wrote is lost to a reset.
//!
//! It claims what the suite claims, RFC 6455 alone: no permessage-deflate (Autobahn scores
//! groups 12/13 UNIMPLEMENTED, as for busbar), no message size ceiling (the 9.x cases send up to
//! 16 MiB), and no pings of its own.
//!
//! Prints `REFERENCE_PORT=<port>` on its own line once bound, then serves until killed.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

/// RFC 6455 section 1.3: the GUID the accept key is hashed with.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Close codes this peer sends.
const PROTOCOL_ERROR: u16 = 1002;
const INVALID_PAYLOAD: u16 = 1007;

/// The longest handshake head this peer reads before refusing it.
const MAX_HEAD: usize = 16 * 1024;

fn main() {
    // The accept computation is proven on RFC 6455's own sample before any socket is opened.
    assert_eq!(
        accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "ws-conformance-reference: the accept key does not match RFC 6455's sample"
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("ws-conformance-reference: bind failed");
    let port = listener
        .local_addr()
        .expect("ws-conformance-reference: no local address")
        .port();
    println!("REFERENCE_PORT={port}");
    std::io::stdout().flush().ok();
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                std::thread::spawn(move || serve(stream));
            }
            Err(e) => eprintln!("ws-conformance-reference: accept error: {e}"),
        }
    }
}

/// One connection: the handshake, then frames until a close or a failure.
fn serve(stream: TcpStream) {
    stream.set_nodelay(true).ok();
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::with_capacity(64 * 1024, read_half);
    let mut writer = stream;
    let Some(key) = read_handshake(&mut reader) else {
        let _ = writer.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return;
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&key)
    );
    if writer.write_all(response.as_bytes()).is_err() {
        return;
    }
    let mut session = Session::default();
    let end = session.run(&mut reader, &mut writer);
    finish(&mut reader, &mut writer, end);
}

/// Read the request head and return its `Sec-WebSocket-Key`, or `None` for anything that is not
/// a version-13 upgrade.
fn read_handshake(reader: &mut impl BufRead) -> Option<String> {
    let mut key = None;
    let mut version_ok = false;
    let mut upgrade_ok = false;
    let mut total = 0usize;
    let mut first = true;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        total += n;
        if total > MAX_HEAD {
            return None;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if first {
            first = false;
            if !line.starts_with("GET ") {
                return None;
            }
            continue;
        }
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "sec-websocket-key" => key = Some(value.to_string()),
            "sec-websocket-version" => version_ok = value == "13",
            "upgrade" => upgrade_ok = value.eq_ignore_ascii_case("websocket"),
            _ => {}
        }
    }
    if version_ok && upgrade_ok {
        key
    } else {
        None
    }
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The socket went away (EOF or an I/O error): nothing more to say.
    Gone,
    /// The peer closed; the reply close (its code echoed, or empty) is written.
    Closed,
    /// The peer broke the protocol; this close code is written.
    Fail(u16),
}

/// A message being received: its type and, for text, where the UTF-8 check stands.
#[derive(Default)]
struct Session {
    /// `Some(text)` while a fragmented message is open.
    open: Option<bool>,
    message: Vec<u8>,
    utf8: Utf8,
}

impl Session {
    fn run(&mut self, reader: &mut impl BufRead, writer: &mut impl Write) -> End {
        loop {
            match self.frame(reader, writer) {
                Ok(None) => {}
                Ok(Some(end)) => return end,
                Err(_) => return End::Gone,
            }
        }
    }

    /// Read and answer one frame. `Ok(Some(_))` ends the session.
    fn frame(
        &mut self,
        reader: &mut impl BufRead,
        writer: &mut impl Write,
    ) -> std::io::Result<Option<End>> {
        let mut head = [0u8; 2];
        if !read_exact_or_eof(reader, &mut head)? {
            return Ok(Some(End::Gone));
        }
        let fin = head[0] & 0x80 != 0;
        let rsv = head[0] & 0x70;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        let control = opcode & 0x08 != 0;
        if rsv != 0 || !masked || !matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA) {
            return Ok(Some(End::Fail(PROTOCOL_ERROR)));
        }
        let len = match head[1] & 0x7F {
            126 => {
                let mut b = [0u8; 2];
                reader.read_exact(&mut b)?;
                u64::from(u16::from_be_bytes(b))
            }
            127 => {
                let mut b = [0u8; 8];
                reader.read_exact(&mut b)?;
                let n = u64::from_be_bytes(b);
                if n >> 63 != 0 {
                    return Ok(Some(End::Fail(PROTOCOL_ERROR)));
                }
                n
            }
            n => u64::from(n),
        };
        if control && (!fin || len > 125) {
            return Ok(Some(End::Fail(PROTOCOL_ERROR)));
        }
        let mut mask = [0u8; 4];
        reader.read_exact(&mut mask)?;

        if control {
            let mut payload = vec![0u8; len as usize];
            reader.read_exact(&mut payload)?;
            unmask(&mut payload, mask, 0);
            return match opcode {
                0x9 => {
                    write_frame(writer, 0xA, &payload)?;
                    Ok(None)
                }
                0xA => Ok(None),
                _ => Ok(Some(self.close(writer, &payload)?)),
            };
        }

        // A data frame: a continuation needs an open message, a new message needs none open.
        let text = match (opcode, self.open) {
            (0x0, Some(text)) => text,
            (0x0, None) | (_, Some(_)) => return Ok(Some(End::Fail(PROTOCOL_ERROR))),
            (op, None) => {
                let text = op == 0x1;
                self.open = Some(text);
                self.message.clear();
                self.utf8 = Utf8::default();
                text
            }
        };

        // The payload, taken as it arrives: text is checked chunk by chunk, so an invalid
        // sequence fails the connection before the rest of the frame is sent.
        let mut left = len;
        let mut offset = 0usize;
        while left > 0 {
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                return Ok(Some(End::Gone));
            }
            let take = chunk.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            let start = self.message.len();
            self.message.extend_from_slice(&chunk[..take]);
            reader.consume(take);
            unmask(&mut self.message[start..], mask, offset);
            offset += take;
            left -= take as u64;
            if text && !self.utf8.feed(&self.message[start..]) {
                return Ok(Some(End::Fail(INVALID_PAYLOAD)));
            }
        }

        if fin {
            if text && !self.utf8.complete() {
                return Ok(Some(End::Fail(INVALID_PAYLOAD)));
            }
            self.open = None;
            let opcode = if text { 0x1 } else { 0x2 };
            write_frame(writer, opcode, &self.message)?;
            self.message = Vec::new();
        }
        Ok(None)
    }

    /// Answer a close frame: echo a valid code (or nothing for an empty close), or fail.
    fn close(&mut self, writer: &mut impl Write, payload: &[u8]) -> std::io::Result<End> {
        match payload {
            [] => {
                write_frame(writer, 0x8, &[])?;
                Ok(End::Closed)
            }
            [_] => Ok(End::Fail(PROTOCOL_ERROR)),
            [hi, lo, reason @ ..] => {
                let code = u16::from_be_bytes([*hi, *lo]);
                if !close_code_valid(code) {
                    return Ok(End::Fail(PROTOCOL_ERROR));
                }
                if std::str::from_utf8(reason).is_err() {
                    return Ok(End::Fail(INVALID_PAYLOAD));
                }
                write_frame(writer, 0x8, &code.to_be_bytes())?;
                Ok(End::Closed)
            }
        }
    }
}

/// Codes a peer may send in a close frame (RFC 6455 section 7.4, the IANA registry): the defined
/// codes that are not reserved for local use, and the registered and private ranges.
fn close_code_valid(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// Write the failure's close if there is one, then half-close and drain, so the peer reads
/// everything written before the socket goes (a close with unread input would reset it).
fn finish(reader: &mut impl Read, writer: &mut TcpStream, end: End) {
    if let End::Fail(code) = end {
        let _ = write_frame(writer, 0x8, &code.to_be_bytes());
    }
    if end == End::Gone {
        return;
    }
    let _ = writer.flush();
    let _ = writer.shutdown(Shutdown::Write);
    let _ = writer.set_read_timeout(Some(Duration::from_secs(5)));
    let mut sink = [0u8; 4096];
    while matches!(reader.read(&mut sink), Ok(n) if n > 0) {}
}

/// `read_exact`, except that EOF before the first byte is `Ok(false)` rather than an error.
fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        match reader.read(&mut buf[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// XOR `bytes` with the mask, `offset` bytes into the payload.
fn unmask(bytes: &mut [u8], mask: [u8; 4], offset: usize) {
    for (i, b) in bytes.iter_mut().enumerate() {
        *b ^= mask[(offset + i) % 4];
    }
}

/// One unmasked, final server frame, written whole.
fn write_frame(writer: &mut impl Write, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => frame.push(n as u8),
        n if n <= usize::from(u16::MAX) => {
            frame.push(126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            frame.push(127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    writer.write_all(&frame)?;
    writer.flush()
}

/// An incremental UTF-8 check that fails on the first byte no valid text could continue with:
/// overlongs, surrogates and code points above U+10FFFF are refused at the byte that makes them
/// so, not when the sequence ends.
#[derive(Debug, Clone, Copy)]
struct Utf8 {
    /// Continuation bytes still owed by the open sequence.
    need: u8,
    /// The range the next continuation byte must fall in.
    lo: u8,
    hi: u8,
}

impl Default for Utf8 {
    fn default() -> Self {
        Utf8 {
            need: 0,
            lo: 0x80,
            hi: 0xBF,
        }
    }
}

impl Utf8 {
    /// Feed bytes; `false` once they cannot be the start of valid text.
    fn feed(&mut self, bytes: &[u8]) -> bool {
        for &b in bytes {
            if self.need == 0 {
                let (need, lo, hi) = match b {
                    0x00..=0x7F => continue,
                    0xC2..=0xDF => (1, 0x80, 0xBF),
                    0xE0 => (2, 0xA0, 0xBF),
                    0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF),
                    0xED => (2, 0x80, 0x9F),
                    0xF0 => (3, 0x90, 0xBF),
                    0xF1..=0xF3 => (3, 0x80, 0xBF),
                    0xF4 => (3, 0x80, 0x8F),
                    _ => return false,
                };
                *self = Utf8 { need, lo, hi };
            } else {
                if !(self.lo..=self.hi).contains(&b) {
                    return false;
                }
                self.need -= 1;
                self.lo = 0x80;
                self.hi = 0xBF;
            }
        }
        true
    }

    /// The text ends on a whole character.
    fn complete(&self) -> bool {
        self.need == 0
    }
}

/// `Sec-WebSocket-Accept` for a key: base64 of the SHA-1 of the key and the GUID.
fn accept_key(key: &str) -> String {
    base64(&sha1(format!("{key}{GUID}").as_bytes()))
}

/// SHA-1 (FIPS 180-4), for the handshake's accept key only.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 16];
        for (slot, word) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*word);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for t in 0..80usize {
            if t >= 16 {
                let v = (w[(t + 13) & 15] ^ w[(t + 8) & 15] ^ w[(t + 2) & 15] ^ w[t & 15])
                    .rotate_left(1);
                w[t & 15] = v;
            }
            let (f, k) = match t {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[t & 15]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (s, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *chunk = v.to_be_bytes();
    }
    out
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A masked client frame, as Autobahn sends one.
    fn client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0x37, 0xFA, 0x21, 0x3D];
        let mut f = vec![first];
        match payload.len() {
            n if n < 126 => f.push(0x80 | n as u8),
            n if n <= 0xFFFF => {
                f.push(0x80 | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(0x80 | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        f.extend_from_slice(&mask);
        let mut body = payload.to_vec();
        unmask(&mut body, mask, 0);
        f.extend_from_slice(&body);
        f
    }

    /// Run a session over `input`; the bytes it wrote and how it ended.
    fn session(input: &[u8]) -> (Vec<u8>, End) {
        let mut reader = BufReader::new(input);
        let mut out = Vec::new();
        let end = Session::default().run(&mut reader, &mut out);
        (out, end)
    }

    #[test]
    fn sha1_and_the_accept_key_match_the_published_vectors() {
        let hex: String = sha1(b"abc").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
        let hex: String = sha1(b"").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }

    #[test]
    fn utf8_fails_at_the_first_impossible_byte() {
        // Valid text, split anywhere, is accepted and completes.
        let text = "κόσμε\u{10FFFF}".as_bytes();
        for cut in 0..text.len() {
            let mut v = Utf8::default();
            assert!(
                v.feed(&text[..cut]) && v.feed(&text[cut..]) && v.complete(),
                "cut {cut}"
            );
        }
        // A surrogate, an overlong and a code point past U+10FFFF fail on their second byte.
        for bad in [[0xED, 0xA0], [0xE0, 0x80], [0xF4, 0x90], [0xC0, 0x80]] {
            let mut v = Utf8::default();
            assert!(!v.feed(&bad), "{bad:02x?}");
        }
        // A truncated sequence is not complete.
        let mut v = Utf8::default();
        assert!(v.feed(&[0xE2, 0x82]) && !v.complete());
    }

    #[test]
    fn a_message_is_echoed_in_kind_and_a_ping_is_answered() {
        let mut input = client_frame(0x81, b"hello");
        input.extend(client_frame(0x89, b"p"));
        input.extend(client_frame(0x82, &[1, 2, 3]));
        input.extend(client_frame(0x88, &1000u16.to_be_bytes()));
        let (out, end) = session(&input);
        assert_eq!(end, End::Closed);
        let mut want = vec![0x81, 5];
        want.extend_from_slice(b"hello");
        want.extend_from_slice(&[0x8A, 1, b'p', 0x82, 3, 1, 2, 3, 0x88, 2, 0x03, 0xE8]);
        assert_eq!(out, want);
    }

    #[test]
    fn a_fragmented_message_is_echoed_whole_and_a_large_one_uses_the_long_length() {
        let mut input = client_frame(0x01, b"ab");
        input.extend(client_frame(0x89, b""));
        input.extend(client_frame(0x80, b"cd"));
        let big = vec![b'x'; 70_000];
        input.extend(client_frame(0x82, &big));
        let (out, end) = session(&input);
        assert_eq!(end, End::Gone);
        assert_eq!(&out[..8], &[0x8A, 0, 0x81, 4, b'a', b'b', b'c', b'd']);
        assert_eq!(&out[8..10], &[0x82, 127]);
        assert_eq!(&out[10..18], &70_000u64.to_be_bytes());
        assert_eq!(out.len(), 18 + 70_000);
    }

    #[test]
    fn a_good_message_ahead_of_a_bad_frame_is_answered_before_the_failure() {
        // RSV2 set; a reserved data opcode; a reserved control opcode; a continuation with
        // nothing open; a fragmented ping; a ping over 125 bytes; a one-byte close; a reserved
        // close code.
        for bad in [
            client_frame(0xA1, b"x"),
            client_frame(0x85, b"x"),
            client_frame(0x8B, b"x"),
            client_frame(0x00, b"x"),
            client_frame(0x09, b"x"),
            client_frame(0x89, &[0; 126]),
            client_frame(0x88, &[3]),
            client_frame(0x88, &1005u16.to_be_bytes()),
        ] {
            let mut input = client_frame(0x81, b"ok");
            input.extend(bad);
            let (out, end) = session(&input);
            assert_eq!(end, End::Fail(PROTOCOL_ERROR));
            assert_eq!(out, vec![0x81, 2, b'o', b'k']);
        }
    }

    #[test]
    fn invalid_text_fails_1007_before_the_rest_of_the_frame_arrives() {
        // The frame claims 100 bytes but only its invalid start is sent: the check must fail on
        // what arrived, not wait for the rest.
        let mut f = client_frame(0x81, &[0xCE, 0xBA, 0xED, 0xA0, 0x80]);
        f[1] = 0x80 | 100;
        let (out, end) = session(&f);
        assert!(out.is_empty());
        assert_eq!(end, End::Fail(INVALID_PAYLOAD));
        // A text message that ends inside a character is 1007 too, and so is a bad close reason.
        assert_eq!(
            session(&client_frame(0x81, &[0xE2, 0x82])).1,
            End::Fail(INVALID_PAYLOAD)
        );
        let mut reason = 1000u16.to_be_bytes().to_vec();
        reason.extend_from_slice(&[0xFF]);
        assert_eq!(
            session(&client_frame(0x88, &reason)).1,
            End::Fail(INVALID_PAYLOAD)
        );
    }

    #[test]
    fn an_unmasked_frame_is_a_protocol_error() {
        let mut f = client_frame(0x81, b"x");
        f[1] &= 0x7F;
        assert_eq!(session(&f).1, End::Fail(PROTOCOL_ERROR));
    }

    #[test]
    fn the_handshake_wants_a_version_13_upgrade() {
        let good = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\
                    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert_eq!(
            read_handshake(&mut BufReader::new(good.as_bytes())).as_deref(),
            Some("dGhlIHNhbXBsZSBub25jZQ==")
        );
        let old = good.replace("Version: 13", "Version: 8");
        assert_eq!(read_handshake(&mut BufReader::new(old.as_bytes())), None);
    }
}
