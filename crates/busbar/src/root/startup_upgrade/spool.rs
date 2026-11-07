// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Composition of native encrypted transient storage with the migration reader.
use busbar_migrations::native_source::{ReadSeek, SourceSpool, SpoolFactory};
use std::io::{self, Write};

pub struct Factory;
struct Writer(super::super::loader::durable::SpoolWriter);

impl SpoolFactory for Factory {
    fn create(&self) -> io::Result<Box<dyn SourceSpool>> {
        Ok(Box::new(Writer(
            super::super::loader::durable::SpoolWriter::new()?,
        )))
    }
}
impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl SourceSpool for Writer {
    fn finish(self: Box<Self>) -> io::Result<Box<dyn ReadSeek + Send>> {
        Ok(Box::new(self.0.finish()?))
    }
}
