// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native message-stream subject (WS-NATIVE-SUBJECT r2). Host target; kernel not present.

use busbar_plugin_abi::records::Reply;
use busbar_ports::transport::TransportOut;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    UnsupportedBodyMode,
    Framing,
    Limit,
    Shape,
    TimerNoProgress,
}

fn upgrade_head(_bytes: &[u8], _max_fields: usize) -> Result<Option<(Reply, usize)>, Failure> {
    Err(Failure::Framing)
}

#[derive(Debug, PartialEq, Eq)]
struct Message {
    stream: u64,
    flags: u32,
    bytes: Vec<u8>,
}

struct EchoState;
impl EchoState {
    fn new(_streams: usize, _messages: usize, _bytes: usize) -> Self {
        Self
    }
    fn body(&mut self, _stream: u64, _flags: u32, _bytes: &[u8]) -> Result<(), Failure> {
        Err(Failure::UnsupportedBodyMode)
    }
    fn full(&mut self, _stream: u64) -> Result<(), Failure> {
        Err(Failure::Shape)
    }
    fn writable(&mut self, _stream: u64) {}
    fn next(&mut self) -> Option<Message> {
        None
    }
    fn end(&mut self, _stream: u64) {}
}

#[derive(Default)]
struct Batch {
    failure: Option<Failure>,
}
impl Batch {
    fn capture(&mut self, _out: TransportOut<'_>, _records: usize, _bytes: usize) {}
}

#[cfg(test)]
#[path = "native_stream_tests.rs"]
mod tests;
