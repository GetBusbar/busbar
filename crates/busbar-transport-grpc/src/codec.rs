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
    type Decode = Vec<u8>;
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
    type Item = Vec<u8>;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        use bytes::Buf;
        if !src.has_remaining() {
            return Ok(None);
        }
        let mut out = vec![0u8; src.remaining()];
        src.copy_to_slice(&mut out);
        Ok(Some(out))
    }
}
