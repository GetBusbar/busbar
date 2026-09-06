// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A byte-blind gRPC codec: messages are `Vec<u8>` in and out, with no protobuf (or any other)
//! meaning attached. `tonic`'s own framing (the 5-byte length-prefix per message, decompression,
//! the `grpc-status` trailer) still runs — this only supplies what the message BODY is, which for
//! a protocol-blind transport is "exactly the bytes the plane handed it, unread".

use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::Status;

/// The codec: `Vec<u8>` messages, no message meaning.
#[derive(Debug, Clone, Default)]
pub(crate) struct RawCodec;

impl Codec for RawCodec {
    type Encode = Vec<u8>;
    /// Decoded messages come out as [`bytes::Bytes`] rather than `Vec<u8>`: the framing layer hands
    /// this decoder a buffer it already owns, and taking the body out of it is a claim on those
    /// bytes rather than a fresh allocation zero-filled and then overwritten.
    type Decode = bytes::Bytes;
    type Encoder = RawEncoder;
    type Decoder = RawDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        RawEncoder
    }
    fn decoder(&mut self) -> Self::Decoder {
        RawDecoder
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RawEncoder;

impl Encoder for RawEncoder {
    type Item = Vec<u8>;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        use bytes::BufMut;
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RawDecoder;

impl Decoder for RawDecoder {
    type Item = bytes::Bytes;
    type Error = Status;

    /// The buffer handed here is always ONE complete message body: the framing layer above reads
    /// the length prefix, waits for exactly that many bytes, and only then calls this. So the body
    /// is never partial, and a zero-length one is a legal message rather than a signal to wait —
    /// `Ok(None)` means "not yet, send more", which for a body that is already complete leaves the
    /// call parked on it forever and takes every message queued behind it down with it. The empty
    /// message is decoded as what it is: zero bytes, delivered.
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        use bytes::Buf;
        // Taken from the buffer as it stands, rather than allocated, zero-filled, and immediately
        // overwritten by a copy — the memset was writing over every byte of every message this
        // transport carries, for a buffer whose whole content is about to be replaced.
        let len = src.remaining();
        Ok(Some(src.copy_to_bytes(len)))
    }
}
