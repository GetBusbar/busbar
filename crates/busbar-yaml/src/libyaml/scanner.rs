//! The tokenizer: a memory-safe port of libyaml 0.2.5's `reader.c` (UTF-8 path) and `scanner.c`.
//!
//! The port follows libyaml (via its line-for-line Rust translation `unsafe-libyaml` 0.2.11, the
//! backend `serde_yaml_ng` 0.10 used) function by function, so that every input yields the same
//! tokens, the same marks and the same errors, at the same point in the stream. Function names
//! keep libyaml's (`fetch_*`, `scan_*`) so the two can be read side by side. The structure of the
//! safe port was informed by `libyaml-safer` 0.3.0 (MIT); where that port departs from libyaml it
//! is corrected here. Licenses: see this crate's `NOTICE`.

use super::error::{Error, Mark};
use std::borrow::Cow;
use std::collections::VecDeque;

/// libyaml's `INPUT_RAW_BUFFER_SIZE`: the reader decodes the input in chunks of this many bytes.
/// Kept because the chunking decides WHEN a malformed byte is reported.
const INPUT_RAW_BUFFER_SIZE: usize = 16384;

/// libyaml's `MAX_NUMBER_LENGTH` for `%YAML` version numbers.
const MAX_NUMBER_LENGTH: u64 = 9;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum ScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TokenData {
    StreamStart,
    StreamEnd,
    VersionDirective { major: i32, minor: i32 },
    TagDirective { handle: Vec<u8>, prefix: Vec<u8> },
    DocumentStart,
    DocumentEnd,
    BlockSequenceStart,
    BlockMappingStart,
    BlockEnd,
    FlowSequenceStart,
    FlowSequenceEnd,
    FlowMappingStart,
    FlowMappingEnd,
    BlockEntry,
    FlowEntry,
    Key,
    Value,
    Alias { value: Vec<u8> },
    Anchor { value: Vec<u8> },
    Tag { handle: Vec<u8>, suffix: Vec<u8> },
    Scalar { value: String, style: ScalarStyle },
}

#[derive(Debug)]
pub(crate) struct Token {
    pub data: TokenData,
    pub start_mark: Mark,
    pub end_mark: Mark,
}

#[derive(Copy, Clone, Debug)]
struct SimpleKey {
    possible: bool,
    required: bool,
    token_number: usize,
    mark: Mark,
}

const NO_SIMPLE_KEY: SimpleKey = SimpleKey {
    possible: false,
    required: false,
    token_number: 0,
    mark: Mark::ZERO,
};

pub(crate) struct Scanner<'input> {
    // ---- reader (libyaml `reader.c`, UTF-8 only: serde_yaml sets the encoding explicitly) ----
    input: Cow<'input, [u8]>,
    /// Start of the raw buffer window (libyaml `raw_buffer.pointer`) in `input`.
    raw_pointer: usize,
    /// End of the raw buffer window (libyaml `raw_buffer.last`) in `input`.
    raw_last: usize,
    /// libyaml `eof`: the read handler returned no more bytes.
    eof: bool,
    /// Byte offset of the next byte to decode (libyaml `offset`).
    offset: u64,
    /// Decoded characters not yet consumed. libyaml terminates the input with a NUL sentinel; here
    /// the end of input is the end of this queue once `eof_terminated` is set.
    buffer: VecDeque<char>,
    eof_terminated: bool,

    // ---- scanner (libyaml `scanner.c`) ----
    mark: Mark,
    stream_start_produced: bool,
    stream_end_produced: bool,
    flow_level: i32,
    tokens: VecDeque<Token>,
    tokens_parsed: usize,
    token_available: bool,
    indents: Vec<i32>,
    indent: i32,
    simple_key_allowed: bool,
    simple_keys: Vec<SimpleKey>,
    /// Sticky error: once the scanner failed, it keeps failing the same way (libyaml's
    /// `parser->error`).
    failed: Option<Error>,
}

fn is_alpha(c: Option<char>) -> bool {
    matches!(c, Some('0'..='9' | 'A'..='Z' | 'a'..='z' | '_' | '-'))
}
fn is_digit(c: Option<char>) -> bool {
    matches!(c, Some('0'..='9'))
}
fn is_hex(c: Option<char>) -> bool {
    matches!(c, Some('0'..='9' | 'A'..='F' | 'a'..='f'))
}
fn as_hex(c: Option<char>) -> u32 {
    c.and_then(|c| c.to_digit(16)).unwrap_or(0)
}
fn is_space(c: Option<char>) -> bool {
    c == Some(' ')
}
fn is_tab(c: Option<char>) -> bool {
    c == Some('\t')
}
fn is_blank(c: Option<char>) -> bool {
    matches!(c, Some(' ' | '\t'))
}
/// libyaml `IS_BREAK`: CR, LF, NEL, LS, PS.
fn is_break(c: Option<char>) -> bool {
    matches!(c, Some('\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}'))
}
/// libyaml `IS_Z`: the NUL sentinel that ends the input.
fn is_z(c: Option<char>) -> bool {
    c.is_none()
}
fn is_breakz(c: Option<char>) -> bool {
    is_break(c) || is_z(c)
}
fn is_blankz(c: Option<char>) -> bool {
    is_blank(c) || is_breakz(c)
}

impl<'input> Scanner<'input> {
    pub fn new(input: Cow<'input, [u8]>) -> Self {
        Scanner {
            input,
            raw_pointer: 0,
            raw_last: 0,
            eof: false,
            offset: 0,
            buffer: VecDeque::new(),
            eof_terminated: false,
            mark: Mark::ZERO,
            stream_start_produced: false,
            stream_end_produced: false,
            flow_level: 0,
            tokens: VecDeque::new(),
            tokens_parsed: 0,
            token_available: false,
            indents: Vec::new(),
            indent: 0,
            simple_key_allowed: false,
            simple_keys: Vec::new(),
            failed: None,
        }
    }

    // ================================ reader ================================

    /// libyaml `yaml_parser_update_raw_buffer` over an in-memory string read handler.
    fn update_raw_buffer(&mut self) {
        let unconsumed = self.raw_last - self.raw_pointer;
        if unconsumed == INPUT_RAW_BUFFER_SIZE {
            // The raw buffer is full and nothing of it was consumed.
            return;
        }
        if self.eof {
            return;
        }
        // libyaml moves the unconsumed bytes to the front of a buffer of INPUT_RAW_BUFFER_SIZE and
        // reads up to the free space from the string handler.
        let free = INPUT_RAW_BUFFER_SIZE - unconsumed;
        let remaining = self.input.len() - self.raw_last;
        let size_read = free.min(remaining);
        self.raw_last += size_read;
        if size_read == 0 {
            self.eof = true;
        }
    }

    /// libyaml `yaml_parser_update_buffer`: decode until `length` characters are available (or the
    /// input ended), decoding whole raw chunks at a time and refusing malformed input exactly as
    /// libyaml's UTF-8 decoder does.
    fn update_buffer(&mut self, length: usize) -> Result<()> {
        if self.eof && self.raw_pointer == self.raw_last {
            return Ok(());
        }
        if self.buffer.len() >= length {
            return Ok(());
        }
        let mut first = true;
        while self.buffer.len() < length {
            if !first || self.raw_pointer == self.raw_last {
                self.update_raw_buffer();
            }
            first = false;
            while self.raw_pointer != self.raw_last {
                let raw = &self.input[self.raw_pointer..self.raw_last];
                let raw_unread = raw.len();
                let octet = raw[0];
                let width = if octet & 0x80 == 0 {
                    1
                } else if octet & 0xE0 == 0xC0 {
                    2
                } else if octet & 0xF0 == 0xE0 {
                    3
                } else if octet & 0xF8 == 0xF0 {
                    4
                } else {
                    0
                };
                if width == 0 {
                    let offset = self.offset;
                    return Err(Error::reader(
                        "invalid leading UTF-8 octet",
                        offset,
                        i32::from(octet),
                    ));
                }
                if width > raw_unread {
                    if self.eof {
                        let offset = self.offset;
                        return Err(Error::reader("incomplete UTF-8 octet sequence", offset, -1));
                    }
                    break;
                }
                let mut value: u32 = u32::from(match width {
                    1 => octet & 0x7F,
                    2 => octet & 0x1F,
                    3 => octet & 0x0F,
                    _ => octet & 0x07,
                });
                for (k, &trailing) in raw.iter().enumerate().take(width).skip(1) {
                    if trailing & 0xC0 != 0x80 {
                        let offset = self.offset + k as u64;
                        return Err(Error::reader(
                            "invalid trailing UTF-8 octet",
                            offset,
                            i32::from(trailing),
                        ));
                    }
                    value = (value << 6) + u32::from(trailing & 0x3F);
                }
                if !(width == 1
                    || width == 2 && value >= 0x80
                    || width == 3 && value >= 0x800
                    || width == 4 && value >= 0x10000)
                {
                    let offset = self.offset;
                    return Err(Error::reader(
                        "invalid length of a UTF-8 sequence",
                        offset,
                        -1,
                    ));
                }
                if (0xD800..=0xDFFF).contains(&value) || value > 0x10FFFF {
                    let offset = self.offset;
                    return Err(Error::reader(
                        "invalid Unicode character",
                        offset,
                        value as i32,
                    ));
                }
                if !(value == 0x9
                    || value == 0xA
                    || value == 0xD
                    || (0x20..=0x7E).contains(&value)
                    || value == 0x85
                    || (0xA0..=0xD7FF).contains(&value)
                    || (0xE000..=0xFFFD).contains(&value)
                    || (0x10000..=0x10FFFF).contains(&value))
                {
                    let offset = self.offset;
                    return Err(Error::reader(
                        "control characters are not allowed",
                        offset,
                        value as i32,
                    ));
                }
                self.raw_pointer += width;
                self.offset += width as u64;
                match char::from_u32(value) {
                    Some(c) => self.buffer.push_back(c),
                    None => {
                        let offset = self.offset;
                        return Err(Error::reader(
                            "invalid Unicode character",
                            offset,
                            value as i32,
                        ));
                    }
                }
            }
            if self.eof {
                self.eof_terminated = true;
                return Ok(());
            }
        }
        if self.offset >= u64::MAX / 2 {
            let offset = self.offset;
            return Err(Error::reader("input is too long", offset, -1));
        }
        Ok(())
    }

    /// libyaml `CACHE`.
    fn cache(&mut self, length: usize) -> Result<()> {
        if self.buffer.len() >= length || self.eof_terminated {
            Ok(())
        } else {
            self.update_buffer(length)
        }
    }

    fn at(&self, offset: usize) -> Option<char> {
        self.buffer.get(offset).copied()
    }
    fn cur(&self) -> Option<char> {
        self.at(0)
    }
    fn check(&self, c: char) -> bool {
        self.cur() == Some(c)
    }
    fn check_at(&self, c: char, offset: usize) -> bool {
        self.at(offset) == Some(c)
    }

    /// libyaml `SKIP`.
    fn skip(&mut self) {
        if let Some(c) = self.buffer.pop_front() {
            self.mark.index += c.len_utf8() as u64;
            self.mark.column += 1;
        }
    }

    /// libyaml `SKIP_LINE`.
    fn skip_line(&mut self) {
        if self.check_at('\r', 0) && self.check_at('\n', 1) {
            self.mark.index += 2;
            self.mark.column = 0;
            self.mark.line += 1;
            self.buffer.pop_front();
            self.buffer.pop_front();
        } else if is_break(self.cur()) {
            if let Some(c) = self.buffer.pop_front() {
                self.mark.index += c.len_utf8() as u64;
                self.mark.column = 0;
                self.mark.line += 1;
            }
        }
    }

    /// libyaml `READ`.
    fn read(&mut self, string: &mut String) {
        if let Some(c) = self.buffer.pop_front() {
            string.push(c);
            self.mark.index += c.len_utf8() as u64;
            self.mark.column += 1;
        }
    }

    /// libyaml `READ` into a byte string (anchors, tags).
    fn read_bytes(&mut self, string: &mut Vec<u8>) {
        if let Some(c) = self.buffer.pop_front() {
            let mut utf8 = [0u8; 4];
            string.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
            self.mark.index += c.len_utf8() as u64;
            self.mark.column += 1;
        }
    }

    /// libyaml `READ_LINE`: CR LF, CR, LF and NEL become LF; LS and PS are kept.
    fn read_line(&mut self, string: &mut String) {
        if self.check_at('\r', 0) && self.check_at('\n', 1) {
            string.push('\n');
            self.buffer.pop_front();
            self.buffer.pop_front();
            self.mark.index += 2;
            self.mark.column = 0;
            self.mark.line += 1;
        } else if matches!(self.cur(), Some('\r' | '\n' | '\u{85}')) {
            if let Some(c) = self.buffer.pop_front() {
                string.push('\n');
                self.mark.index += c.len_utf8() as u64;
                self.mark.column = 0;
                self.mark.line += 1;
            }
        } else if matches!(self.cur(), Some('\u{2028}' | '\u{2029}')) {
            if let Some(c) = self.buffer.pop_front() {
                string.push(c);
                self.mark.index += 3;
                self.mark.column = 0;
                self.mark.line += 1;
            }
        }
    }

    // ================================ token queue ================================

    fn scanner_error<T>(
        &mut self,
        context: Option<&'static str>,
        context_mark: Mark,
        problem: &'static str,
    ) -> Result<T> {
        let error = Error::scanner(context, context_mark, problem, self.mark);
        self.failed = Some(error.clone());
        Err(error)
    }

    fn fail<T>(&mut self, error: Error) -> Result<T> {
        self.failed = Some(error.clone());
        Err(error)
    }

    /// libyaml `PEEK_TOKEN`.
    pub fn peek(&mut self) -> Result<&Token> {
        if !self.token_available {
            self.fetch_more_tokens()?;
        }
        match self.tokens.front() {
            Some(token) => Ok(token),
            None => Err(Error::internal("the scanner produced no token")),
        }
    }

    /// libyaml `SKIP_TOKEN`.
    pub fn skip_token(&mut self) -> Option<Token> {
        self.token_available = false;
        self.tokens_parsed = self.tokens_parsed.wrapping_add(1);
        let token = self.tokens.pop_front();
        self.stream_end_produced = matches!(
            token,
            Some(Token {
                data: TokenData::StreamEnd,
                ..
            })
        );
        token
    }

    pub fn stream_end_produced(&self) -> bool {
        self.stream_end_produced
    }

    /// libyaml `yaml_parser_fetch_more_tokens`.
    fn fetch_more_tokens(&mut self) -> Result<()> {
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        loop {
            let mut need_more_tokens = false;
            if self.tokens.is_empty() {
                need_more_tokens = true;
            } else {
                if let Err(error) = self.stale_simple_keys() {
                    return self.fail(error);
                }
                for simple_key in &self.simple_keys {
                    if simple_key.possible && simple_key.token_number == self.tokens_parsed {
                        need_more_tokens = true;
                        break;
                    }
                }
            }
            if !need_more_tokens {
                break;
            }
            if let Err(error) = self.fetch_next_token() {
                return self.fail(error);
            }
        }
        self.token_available = true;
        Ok(())
    }

    /// libyaml `yaml_parser_fetch_next_token`.
    fn fetch_next_token(&mut self) -> Result<()> {
        self.cache(1)?;
        if !self.stream_start_produced {
            self.fetch_stream_start();
            return Ok(());
        }
        self.scan_to_next_token()?;
        self.stale_simple_keys()?;
        self.unroll_indent(self.mark.column as i64);
        self.cache(4)?;
        if is_z(self.cur()) {
            return self.fetch_stream_end();
        }
        if self.mark.column == 0 && self.check('%') {
            return self.fetch_directive();
        }
        if self.mark.column == 0
            && self.check_at('-', 0)
            && self.check_at('-', 1)
            && self.check_at('-', 2)
            && is_blankz(self.at(3))
        {
            return self.fetch_document_indicator(TokenData::DocumentStart);
        }
        if self.mark.column == 0
            && self.check_at('.', 0)
            && self.check_at('.', 1)
            && self.check_at('.', 2)
            && is_blankz(self.at(3))
        {
            return self.fetch_document_indicator(TokenData::DocumentEnd);
        }
        if self.check('[') {
            return self.fetch_flow_collection_start(TokenData::FlowSequenceStart);
        }
        if self.check('{') {
            return self.fetch_flow_collection_start(TokenData::FlowMappingStart);
        }
        if self.check(']') {
            return self.fetch_flow_collection_end(TokenData::FlowSequenceEnd);
        }
        if self.check('}') {
            return self.fetch_flow_collection_end(TokenData::FlowMappingEnd);
        }
        if self.check(',') {
            return self.fetch_flow_entry();
        }
        if self.check('-') && is_blankz(self.at(1)) {
            return self.fetch_block_entry();
        }
        if self.check('?') && (self.flow_level != 0 || is_blankz(self.at(1))) {
            return self.fetch_key();
        }
        if self.check(':') && (self.flow_level != 0 || is_blankz(self.at(1))) {
            return self.fetch_value();
        }
        if self.check('*') {
            return self.fetch_anchor(true);
        }
        if self.check('&') {
            return self.fetch_anchor(false);
        }
        if self.check('!') {
            return self.fetch_tag();
        }
        if self.check('|') && self.flow_level == 0 {
            return self.fetch_block_scalar(true);
        }
        if self.check('>') && self.flow_level == 0 {
            return self.fetch_block_scalar(false);
        }
        if self.check('\'') {
            return self.fetch_flow_scalar(true);
        }
        if self.check('"') {
            return self.fetch_flow_scalar(false);
        }
        let c = self.cur();
        if !(is_blankz(c)
            || matches!(
                c,
                Some(
                    '-' | '?'
                        | ':'
                        | ','
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '#'
                        | '&'
                        | '*'
                        | '!'
                        | '|'
                        | '>'
                        | '\''
                        | '"'
                        | '%'
                        | '@'
                        | '`'
                )
            ))
            || self.check('-') && !is_blank(self.at(1))
            || self.flow_level == 0
                && (self.check('?') || self.check(':'))
                && !is_blankz(self.at(1))
        {
            return self.fetch_plain_scalar();
        }
        let mark = self.mark;
        self.scanner_error(
            Some("while scanning for the next token"),
            mark,
            "found character that cannot start any token",
        )
    }

    /// libyaml `yaml_parser_stale_simple_keys`.
    fn stale_simple_keys(&mut self) -> Result<()> {
        let mark = self.mark;
        for i in 0..self.simple_keys.len() {
            let simple_key = self.simple_keys[i];
            if simple_key.possible
                && (simple_key.mark.line < mark.line || simple_key.mark.index + 1024 < mark.index)
            {
                if simple_key.required {
                    return self.scanner_error(
                        Some("while scanning a simple key"),
                        simple_key.mark,
                        "could not find expected ':'",
                    );
                }
                self.simple_keys[i].possible = false;
            }
        }
        Ok(())
    }

    /// libyaml `yaml_parser_save_simple_key`.
    fn save_simple_key(&mut self) -> Result<()> {
        let required = self.flow_level == 0 && i64::from(self.indent) == self.mark.column as i64;
        if self.simple_key_allowed {
            let simple_key = SimpleKey {
                possible: true,
                required,
                token_number: self.tokens_parsed + self.tokens.len(),
                mark: self.mark,
            };
            self.remove_simple_key()?;
            if let Some(last) = self.simple_keys.last_mut() {
                *last = simple_key;
            }
        }
        Ok(())
    }

    /// libyaml `yaml_parser_remove_simple_key`.
    fn remove_simple_key(&mut self) -> Result<()> {
        if let Some(simple_key) = self.simple_keys.last().copied() {
            if simple_key.possible && simple_key.required {
                return self.scanner_error(
                    Some("while scanning a simple key"),
                    simple_key.mark,
                    "could not find expected ':'",
                );
            }
        }
        if let Some(last) = self.simple_keys.last_mut() {
            last.possible = false;
        }
        Ok(())
    }

    /// libyaml `yaml_parser_increase_flow_level`.
    fn increase_flow_level(&mut self) -> Result<()> {
        self.simple_keys.push(NO_SIMPLE_KEY);
        if self.flow_level == i32::MAX {
            let error = Error::memory();
            return self.fail(error);
        }
        self.flow_level += 1;
        Ok(())
    }

    /// libyaml `yaml_parser_decrease_flow_level`.
    fn decrease_flow_level(&mut self) {
        if self.flow_level != 0 {
            self.flow_level -= 1;
            self.simple_keys.pop();
        }
    }

    /// libyaml `yaml_parser_roll_indent`. `number` is the token number to insert before, or
    /// `None` to append.
    fn roll_indent(
        &mut self,
        column: i64,
        number: Option<usize>,
        data: TokenData,
        mark: Mark,
    ) -> Result<()> {
        if self.flow_level != 0 {
            return Ok(());
        }
        if i64::from(self.indent) < column {
            self.indents.push(self.indent);
            if column > i64::from(i32::MAX) {
                let error = Error::memory();
                return self.fail(error);
            }
            self.indent = column as i32;
            let token = Token {
                data,
                start_mark: mark,
                end_mark: mark,
            };
            match number {
                None => self.tokens.push_back(token),
                Some(number) => {
                    let at = number
                        .wrapping_sub(self.tokens_parsed)
                        .min(self.tokens.len());
                    self.tokens.insert(at, token);
                }
            }
        }
        Ok(())
    }

    /// libyaml `yaml_parser_unroll_indent`.
    fn unroll_indent(&mut self, column: i64) {
        if self.flow_level != 0 {
            return;
        }
        while i64::from(self.indent) > column {
            self.tokens.push_back(Token {
                data: TokenData::BlockEnd,
                start_mark: self.mark,
                end_mark: self.mark,
            });
            self.indent = self.indents.pop().unwrap_or(-1);
        }
    }

    fn push_simple(&mut self, data: TokenData) {
        let start_mark = self.mark;
        self.skip();
        let end_mark = self.mark;
        self.tokens.push_back(Token {
            data,
            start_mark,
            end_mark,
        });
    }

    fn fetch_stream_start(&mut self) {
        self.indent = -1;
        self.simple_keys.push(NO_SIMPLE_KEY);
        self.simple_key_allowed = true;
        self.stream_start_produced = true;
        self.tokens.push_back(Token {
            data: TokenData::StreamStart,
            start_mark: self.mark,
            end_mark: self.mark,
        });
    }

    fn fetch_stream_end(&mut self) -> Result<()> {
        // Force a new line.
        if self.mark.column != 0 {
            self.mark.column = 0;
            self.mark.line += 1;
        }
        self.unroll_indent(-1);
        self.remove_simple_key()?;
        self.simple_key_allowed = false;
        self.tokens.push_back(Token {
            data: TokenData::StreamEnd,
            start_mark: self.mark,
            end_mark: self.mark,
        });
        Ok(())
    }

    fn fetch_directive(&mut self) -> Result<()> {
        self.unroll_indent(-1);
        self.remove_simple_key()?;
        self.simple_key_allowed = false;
        let token = self.scan_directive()?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_document_indicator(&mut self, data: TokenData) -> Result<()> {
        self.unroll_indent(-1);
        self.remove_simple_key()?;
        self.simple_key_allowed = false;
        let start_mark = self.mark;
        self.skip();
        self.skip();
        self.skip();
        let end_mark = self.mark;
        self.tokens.push_back(Token {
            data,
            start_mark,
            end_mark,
        });
        Ok(())
    }

    fn fetch_flow_collection_start(&mut self, data: TokenData) -> Result<()> {
        self.save_simple_key()?;
        self.increase_flow_level()?;
        self.simple_key_allowed = true;
        self.push_simple(data);
        Ok(())
    }

    fn fetch_flow_collection_end(&mut self, data: TokenData) -> Result<()> {
        self.remove_simple_key()?;
        self.decrease_flow_level();
        self.simple_key_allowed = false;
        self.push_simple(data);
        Ok(())
    }

    fn fetch_flow_entry(&mut self) -> Result<()> {
        self.remove_simple_key()?;
        self.simple_key_allowed = true;
        self.push_simple(TokenData::FlowEntry);
        Ok(())
    }

    fn fetch_block_entry(&mut self) -> Result<()> {
        if self.flow_level == 0 {
            if !self.simple_key_allowed {
                let mark = self.mark;
                return self.scanner_error(
                    None,
                    mark,
                    "block sequence entries are not allowed in this context",
                );
            }
            let (column, mark) = (self.mark.column as i64, self.mark);
            self.roll_indent(column, None, TokenData::BlockSequenceStart, mark)?;
        }
        self.remove_simple_key()?;
        self.simple_key_allowed = true;
        self.push_simple(TokenData::BlockEntry);
        Ok(())
    }

    fn fetch_key(&mut self) -> Result<()> {
        if self.flow_level == 0 {
            if !self.simple_key_allowed {
                let mark = self.mark;
                return self.scanner_error(
                    None,
                    mark,
                    "mapping keys are not allowed in this context",
                );
            }
            let (column, mark) = (self.mark.column as i64, self.mark);
            self.roll_indent(column, None, TokenData::BlockMappingStart, mark)?;
        }
        self.remove_simple_key()?;
        self.simple_key_allowed = self.flow_level == 0;
        self.push_simple(TokenData::Key);
        Ok(())
    }

    fn fetch_value(&mut self) -> Result<()> {
        let simple_key = self.simple_keys.last().copied().unwrap_or(NO_SIMPLE_KEY);
        if simple_key.possible {
            let at = simple_key
                .token_number
                .wrapping_sub(self.tokens_parsed)
                .min(self.tokens.len());
            self.tokens.insert(
                at,
                Token {
                    data: TokenData::Key,
                    start_mark: simple_key.mark,
                    end_mark: simple_key.mark,
                },
            );
            self.roll_indent(
                simple_key.mark.column as i64,
                Some(simple_key.token_number),
                TokenData::BlockMappingStart,
                simple_key.mark,
            )?;
            if let Some(last) = self.simple_keys.last_mut() {
                last.possible = false;
            }
            self.simple_key_allowed = false;
        } else {
            if self.flow_level == 0 {
                if !self.simple_key_allowed {
                    let mark = self.mark;
                    return self.scanner_error(
                        None,
                        mark,
                        "mapping values are not allowed in this context",
                    );
                }
                let (column, mark) = (self.mark.column as i64, self.mark);
                self.roll_indent(column, None, TokenData::BlockMappingStart, mark)?;
            }
            self.simple_key_allowed = self.flow_level == 0;
        }
        self.push_simple(TokenData::Value);
        Ok(())
    }

    fn fetch_anchor(&mut self, alias: bool) -> Result<()> {
        self.save_simple_key()?;
        self.simple_key_allowed = false;
        let token = self.scan_anchor(alias)?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_tag(&mut self) -> Result<()> {
        self.save_simple_key()?;
        self.simple_key_allowed = false;
        let token = self.scan_tag()?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_block_scalar(&mut self, literal: bool) -> Result<()> {
        self.remove_simple_key()?;
        self.simple_key_allowed = true;
        let token = self.scan_block_scalar(literal)?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_flow_scalar(&mut self, single: bool) -> Result<()> {
        self.save_simple_key()?;
        self.simple_key_allowed = false;
        let token = self.scan_flow_scalar(single)?;
        self.tokens.push_back(token);
        Ok(())
    }

    fn fetch_plain_scalar(&mut self) -> Result<()> {
        self.save_simple_key()?;
        self.simple_key_allowed = false;
        let token = self.scan_plain_scalar()?;
        self.tokens.push_back(token);
        Ok(())
    }

    // ================================ scanners ================================

    /// libyaml `yaml_parser_scan_to_next_token`.
    fn scan_to_next_token(&mut self) -> Result<()> {
        loop {
            self.cache(1)?;
            if self.mark.column == 0 && self.check('\u{feff}') {
                self.skip();
            }
            self.cache(1)?;
            while self.check(' ')
                || (self.flow_level != 0 || !self.simple_key_allowed) && self.check('\t')
            {
                self.skip();
                self.cache(1)?;
            }
            if self.check('#') {
                while !is_breakz(self.cur()) {
                    self.skip();
                    self.cache(1)?;
                }
            }
            if !is_break(self.cur()) {
                break;
            }
            self.cache(2)?;
            self.skip_line();
            if self.flow_level == 0 {
                self.simple_key_allowed = true;
            }
        }
        Ok(())
    }

    /// libyaml `yaml_parser_scan_directive`.
    fn scan_directive(&mut self) -> Result<Token> {
        let start_mark = self.mark;
        self.skip();
        let name = self.scan_directive_name(start_mark)?;
        let data = if name == "YAML" {
            let (major, minor) = self.scan_version_directive_value(start_mark)?;
            TokenData::VersionDirective { major, minor }
        } else if name == "TAG" {
            let (handle, prefix) = self.scan_tag_directive_value(start_mark)?;
            TokenData::TagDirective { handle, prefix }
        } else {
            return self.scanner_error(
                Some("while scanning a directive"),
                start_mark,
                "found unknown directive name",
            );
        };
        let end_mark = self.mark;
        self.cache(1)?;
        while is_blank(self.cur()) {
            self.skip();
            self.cache(1)?;
        }
        if self.check('#') {
            while !is_breakz(self.cur()) {
                self.skip();
                self.cache(1)?;
            }
        }
        if !is_breakz(self.cur()) {
            return self.scanner_error(
                Some("while scanning a directive"),
                start_mark,
                "did not find expected comment or line break",
            );
        }
        if is_break(self.cur()) {
            self.cache(2)?;
            self.skip_line();
        }
        Ok(Token {
            data,
            start_mark,
            end_mark,
        })
    }

    fn scan_directive_name(&mut self, start_mark: Mark) -> Result<String> {
        let mut string = String::new();
        self.cache(1)?;
        while is_alpha(self.cur()) {
            self.read(&mut string);
            self.cache(1)?;
        }
        if string.is_empty() {
            self.scanner_error(
                Some("while scanning a directive"),
                start_mark,
                "could not find expected directive name",
            )
        } else if !is_blankz(self.cur()) {
            self.scanner_error(
                Some("while scanning a directive"),
                start_mark,
                "found unexpected non-alphabetical character",
            )
        } else {
            Ok(string)
        }
    }

    fn scan_version_directive_value(&mut self, start_mark: Mark) -> Result<(i32, i32)> {
        self.cache(1)?;
        while is_blank(self.cur()) {
            self.skip();
            self.cache(1)?;
        }
        let major = self.scan_version_directive_number(start_mark)?;
        if !self.check('.') {
            return self.scanner_error(
                Some("while scanning a %YAML directive"),
                start_mark,
                "did not find expected digit or '.' character",
            );
        }
        self.skip();
        let minor = self.scan_version_directive_number(start_mark)?;
        Ok((major, minor))
    }

    fn scan_version_directive_number(&mut self, start_mark: Mark) -> Result<i32> {
        let mut value: i32 = 0;
        let mut length: u64 = 0;
        self.cache(1)?;
        while is_digit(self.cur()) {
            length += 1;
            if length > MAX_NUMBER_LENGTH {
                return self.scanner_error(
                    Some("while scanning a %YAML directive"),
                    start_mark,
                    "found extremely long version number",
                );
            }
            let digit = self.cur().and_then(|c| c.to_digit(10)).unwrap_or(0) as i32;
            value = value.wrapping_mul(10).wrapping_add(digit);
            self.skip();
            self.cache(1)?;
        }
        if length == 0 {
            return self.scanner_error(
                Some("while scanning a %YAML directive"),
                start_mark,
                "did not find expected version number",
            );
        }
        Ok(value)
    }

    fn scan_tag_directive_value(&mut self, start_mark: Mark) -> Result<(Vec<u8>, Vec<u8>)> {
        self.cache(1)?;
        loop {
            if is_blank(self.cur()) {
                self.skip();
                self.cache(1)?;
                continue;
            }
            let handle = self.scan_tag_handle(true, start_mark)?;
            self.cache(1)?;
            if !is_blank(self.cur()) {
                return self.scanner_error(
                    Some("while scanning a %TAG directive"),
                    start_mark,
                    "did not find expected whitespace",
                );
            }
            while is_blank(self.cur()) {
                self.skip();
                self.cache(1)?;
            }
            let prefix = self.scan_tag_uri(true, true, None, start_mark)?;
            self.cache(1)?;
            if !is_blankz(self.cur()) {
                return self.scanner_error(
                    Some("while scanning a %TAG directive"),
                    start_mark,
                    "did not find expected whitespace or line break",
                );
            }
            return Ok((handle, prefix));
        }
    }

    fn scan_anchor(&mut self, alias: bool) -> Result<Token> {
        let mut length = 0;
        let mut string = Vec::new();
        let start_mark = self.mark;
        self.skip();
        self.cache(1)?;
        while is_alpha(self.cur()) {
            self.read_bytes(&mut string);
            self.cache(1)?;
            length += 1;
        }
        let end_mark = self.mark;
        if length == 0
            || !(is_blankz(self.cur())
                || matches!(
                    self.cur(),
                    Some('?' | ':' | ',' | ']' | '}' | '%' | '@' | '`')
                ))
        {
            return self.scanner_error(
                Some(if alias {
                    "while scanning an alias"
                } else {
                    "while scanning an anchor"
                }),
                start_mark,
                "did not find expected alphabetic or numeric character",
            );
        }
        Ok(Token {
            data: if alias {
                TokenData::Alias { value: string }
            } else {
                TokenData::Anchor { value: string }
            },
            start_mark,
            end_mark,
        })
    }

    fn scan_tag(&mut self) -> Result<Token> {
        let start_mark = self.mark;
        self.cache(2)?;
        let (handle, suffix);
        if self.check_at('<', 1) {
            // Verbatim tag: `!<...>`.
            self.skip();
            self.skip();
            let uri = self.scan_tag_uri(true, false, None, start_mark)?;
            if !self.check('>') {
                return self.scanner_error(
                    Some("while scanning a tag"),
                    start_mark,
                    "did not find the expected '>'",
                );
            }
            self.skip();
            handle = Vec::new();
            suffix = uri;
        } else {
            let first = self.scan_tag_handle(false, start_mark)?;
            if first.len() > 1 && first.first() == Some(&b'!') && first.last() == Some(&b'!') {
                // `!handle!suffix`.
                suffix = self.scan_tag_uri(false, false, None, start_mark)?;
                handle = first;
            } else {
                // `!suffix` (the handle read so far is the head of the suffix), or a lone `!`.
                let uri = self.scan_tag_uri(false, false, Some(&first), start_mark)?;
                if uri.is_empty() {
                    handle = Vec::new();
                    suffix = b"!".to_vec();
                } else {
                    handle = b"!".to_vec();
                    suffix = uri;
                }
            }
        }
        self.cache(1)?;
        if !is_blankz(self.cur()) && (self.flow_level == 0 || !self.check(',')) {
            return self.scanner_error(
                Some("while scanning a tag"),
                start_mark,
                "did not find expected whitespace or line break",
            );
        }
        let end_mark = self.mark;
        Ok(Token {
            data: TokenData::Tag { handle, suffix },
            start_mark,
            end_mark,
        })
    }

    fn scan_tag_handle(&mut self, directive: bool, start_mark: Mark) -> Result<Vec<u8>> {
        let mut string = Vec::new();
        self.cache(1)?;
        if !self.check('!') {
            return self.scanner_error(
                Some(if directive {
                    "while scanning a tag directive"
                } else {
                    "while scanning a tag"
                }),
                start_mark,
                "did not find expected '!'",
            );
        }
        self.read_bytes(&mut string);
        self.cache(1)?;
        while is_alpha(self.cur()) {
            self.read_bytes(&mut string);
            self.cache(1)?;
        }
        if self.check('!') {
            self.read_bytes(&mut string);
        } else if directive && string != b"!" {
            return self.scanner_error(
                Some("while parsing a tag directive"),
                start_mark,
                "did not find expected '!'",
            );
        }
        Ok(string)
    }

    fn scan_tag_uri(
        &mut self,
        uri_char: bool,
        directive: bool,
        head: Option<&[u8]>,
        start_mark: Mark,
    ) -> Result<Vec<u8>> {
        let head = head.unwrap_or(b"");
        let mut length = head.len();
        let mut string = Vec::new();
        // The head's leading '!' is not copied.
        if length > 1 {
            string.extend_from_slice(&head[1..]);
        }
        self.cache(1)?;
        while is_alpha(self.cur())
            || matches!(
                self.cur(),
                Some(
                    ';' | '/'
                        | '?'
                        | ':'
                        | '@'
                        | '&'
                        | '='
                        | '+'
                        | '$'
                        | '.'
                        | '%'
                        | '!'
                        | '~'
                        | '*'
                        | '\''
                        | '('
                        | ')'
                )
            )
            || uri_char && matches!(self.cur(), Some(',' | '[' | ']'))
        {
            if self.check('%') {
                self.scan_uri_escapes(directive, start_mark, &mut string)?;
            } else {
                self.read_bytes(&mut string);
            }
            length += 1;
            self.cache(1)?;
        }
        if length == 0 {
            return self.scanner_error(
                Some(if directive {
                    "while parsing a %TAG directive"
                } else {
                    "while parsing a tag"
                }),
                start_mark,
                "did not find expected tag URI",
            );
        }
        Ok(string)
    }

    fn scan_uri_escapes(
        &mut self,
        directive: bool,
        start_mark: Mark,
        string: &mut Vec<u8>,
    ) -> Result<()> {
        let context = if directive {
            "while parsing a %TAG directive"
        } else {
            "while parsing a tag"
        };
        let mut width = 0;
        loop {
            self.cache(3)?;
            if !(self.check('%') && is_hex(self.at(1)) && is_hex(self.at(2))) {
                return self.scanner_error(
                    Some(context),
                    start_mark,
                    "did not find URI escaped octet",
                );
            }
            let octet = ((as_hex(self.at(1)) << 4) + as_hex(self.at(2))) as u8;
            if width == 0 {
                width = if octet & 0x80 == 0 {
                    1
                } else if octet & 0xE0 == 0xC0 {
                    2
                } else if octet & 0xF0 == 0xE0 {
                    3
                } else if octet & 0xF8 == 0xF0 {
                    4
                } else {
                    0
                };
                if width == 0 {
                    return self.scanner_error(
                        Some(context),
                        start_mark,
                        "found an incorrect leading UTF-8 octet",
                    );
                }
            } else if octet & 0xC0 != 0x80 {
                return self.scanner_error(
                    Some(context),
                    start_mark,
                    "found an incorrect trailing UTF-8 octet",
                );
            }
            string.push(octet);
            self.skip();
            self.skip();
            self.skip();
            width -= 1;
            if width == 0 {
                break;
            }
        }
        Ok(())
    }

    fn scan_block_scalar(&mut self, literal: bool) -> Result<Token> {
        let mut string = String::new();
        let mut leading_break = String::new();
        let mut trailing_breaks = String::new();
        let mut chomping: i32 = 0;
        let mut increment: i32 = 0;
        let mut indent: i32 = 0;
        let mut leading_blank = false;
        let start_mark = self.mark;
        self.skip();
        self.cache(1)?;
        if self.check('+') || self.check('-') {
            chomping = if self.check('+') { 1 } else { -1 };
            self.skip();
            self.cache(1)?;
            if is_digit(self.cur()) {
                if self.check('0') {
                    return self.scanner_error(
                        Some("while scanning a block scalar"),
                        start_mark,
                        "found an indentation indicator equal to 0",
                    );
                }
                increment = self.cur().and_then(|c| c.to_digit(10)).unwrap_or(0) as i32;
                self.skip();
            }
        } else if is_digit(self.cur()) {
            if self.check('0') {
                return self.scanner_error(
                    Some("while scanning a block scalar"),
                    start_mark,
                    "found an indentation indicator equal to 0",
                );
            }
            increment = self.cur().and_then(|c| c.to_digit(10)).unwrap_or(0) as i32;
            self.skip();
            self.cache(1)?;
            if self.check('+') || self.check('-') {
                chomping = if self.check('+') { 1 } else { -1 };
                self.skip();
            }
        }
        self.cache(1)?;
        while is_blank(self.cur()) {
            self.skip();
            self.cache(1)?;
        }
        if self.check('#') {
            while !is_breakz(self.cur()) {
                self.skip();
                self.cache(1)?;
            }
        }
        if !is_breakz(self.cur()) {
            return self.scanner_error(
                Some("while scanning a block scalar"),
                start_mark,
                "did not find expected comment or line break",
            );
        }
        if is_break(self.cur()) {
            self.cache(2)?;
            self.skip_line();
        }
        let mut end_mark = self.mark;
        if increment != 0 {
            indent = if self.indent >= 0 {
                self.indent + increment
            } else {
                increment
            };
        }
        self.scan_block_scalar_breaks(
            &mut indent,
            &mut trailing_breaks,
            start_mark,
            &mut end_mark,
        )?;
        self.cache(1)?;
        while self.mark.column as i64 == i64::from(indent) && !is_z(self.cur()) {
            let trailing_blank = is_blank(self.cur());
            if !literal && leading_break.starts_with('\n') && !leading_blank && !trailing_blank {
                if trailing_breaks.is_empty() {
                    string.push(' ');
                }
                leading_break.clear();
            } else {
                string.push_str(&leading_break);
                leading_break.clear();
            }
            string.push_str(&trailing_breaks);
            trailing_breaks.clear();
            leading_blank = is_blank(self.cur());
            while !is_breakz(self.cur()) {
                self.read(&mut string);
                self.cache(1)?;
            }
            self.cache(2)?;
            self.read_line(&mut leading_break);
            self.scan_block_scalar_breaks(
                &mut indent,
                &mut trailing_breaks,
                start_mark,
                &mut end_mark,
            )?;
        }
        if chomping != -1 {
            string.push_str(&leading_break);
        }
        if chomping == 1 {
            string.push_str(&trailing_breaks);
        }
        Ok(Token {
            data: TokenData::Scalar {
                value: string,
                style: if literal {
                    ScalarStyle::Literal
                } else {
                    ScalarStyle::Folded
                },
            },
            start_mark,
            end_mark,
        })
    }

    fn scan_block_scalar_breaks(
        &mut self,
        indent: &mut i32,
        breaks: &mut String,
        start_mark: Mark,
        end_mark: &mut Mark,
    ) -> Result<()> {
        let mut max_indent: i32 = 0;
        *end_mark = self.mark;
        loop {
            self.cache(1)?;
            while (*indent == 0 || (self.mark.column as i64) < i64::from(*indent))
                && is_space(self.cur())
            {
                self.skip();
                self.cache(1)?;
            }
            if self.mark.column as i64 > i64::from(max_indent) {
                max_indent = self.mark.column as i32;
            }
            if (*indent == 0 || (self.mark.column as i64) < i64::from(*indent))
                && is_tab(self.cur())
            {
                return self.scanner_error(
                    Some("while scanning a block scalar"),
                    start_mark,
                    "found a tab character where an indentation space is expected",
                );
            }
            if !is_break(self.cur()) {
                break;
            }
            self.cache(2)?;
            self.read_line(breaks);
            *end_mark = self.mark;
        }
        if *indent == 0 {
            *indent = max_indent;
            if *indent < self.indent + 1 {
                *indent = self.indent + 1;
            }
            if *indent < 1 {
                *indent = 1;
            }
        }
        Ok(())
    }

    fn scan_flow_scalar(&mut self, single: bool) -> Result<Token> {
        let mut string = String::new();
        let mut leading_break = String::new();
        let mut trailing_breaks = String::new();
        let mut whitespaces = String::new();
        let start_mark = self.mark;
        let quote = if single { '\'' } else { '"' };
        self.skip();
        loop {
            self.cache(4)?;
            if self.mark.column == 0
                && (self.check_at('-', 0) && self.check_at('-', 1) && self.check_at('-', 2)
                    || self.check_at('.', 0) && self.check_at('.', 1) && self.check_at('.', 2))
                && is_blankz(self.at(3))
            {
                return self.scanner_error(
                    Some("while scanning a quoted scalar"),
                    start_mark,
                    "found unexpected document indicator",
                );
            } else if is_z(self.cur()) {
                return self.scanner_error(
                    Some("while scanning a quoted scalar"),
                    start_mark,
                    "found unexpected end of stream",
                );
            }
            self.cache(2)?;
            let mut leading_blanks = false;
            while !is_blankz(self.cur()) {
                if single && self.check_at('\'', 0) && self.check_at('\'', 1) {
                    string.push('\'');
                    self.skip();
                    self.skip();
                } else {
                    if self.check(quote) {
                        break;
                    }
                    if !single && self.check('\\') && is_break(self.at(1)) {
                        self.cache(3)?;
                        self.skip();
                        self.skip_line();
                        leading_blanks = true;
                        break;
                    } else if !single && self.check('\\') {
                        let mut code_length = 0usize;
                        match self.at(1) {
                            Some('0') => string.push('\0'),
                            Some('a') => string.push('\x07'),
                            Some('b') => string.push('\x08'),
                            Some('t' | '\t') => string.push('\t'),
                            Some('n') => string.push('\n'),
                            Some('v') => string.push('\x0B'),
                            Some('f') => string.push('\x0C'),
                            Some('r') => string.push('\r'),
                            Some('e') => string.push('\x1B'),
                            Some(' ') => string.push(' '),
                            Some('"') => string.push('"'),
                            Some('/') => string.push('/'),
                            Some('\\') => string.push('\\'),
                            Some('N') => string.push('\u{85}'),
                            Some('_') => string.push('\u{A0}'),
                            Some('L') => string.push('\u{2028}'),
                            Some('P') => string.push('\u{2029}'),
                            Some('x') => code_length = 2,
                            Some('u') => code_length = 4,
                            Some('U') => code_length = 8,
                            _ => {
                                return self.scanner_error(
                                    Some("while parsing a quoted scalar"),
                                    start_mark,
                                    "found unknown escape character",
                                );
                            }
                        }
                        self.skip();
                        self.skip();
                        if code_length != 0 {
                            let mut value: u32 = 0;
                            self.cache(code_length)?;
                            for k in 0..code_length {
                                if !is_hex(self.at(k)) {
                                    return self.scanner_error(
                                        Some("while parsing a quoted scalar"),
                                        start_mark,
                                        "did not find expected hexadecimal number",
                                    );
                                }
                                value = (value << 4).wrapping_add(as_hex(self.at(k)));
                            }
                            if (0xD800..=0xDFFF).contains(&value) || value > 0x10FFFF {
                                return self.scanner_error(
                                    Some("while parsing a quoted scalar"),
                                    start_mark,
                                    "found invalid Unicode character escape code",
                                );
                            }
                            match char::from_u32(value) {
                                Some(c) => string.push(c),
                                None => {
                                    return self.scanner_error(
                                        Some("while parsing a quoted scalar"),
                                        start_mark,
                                        "found invalid Unicode character escape code",
                                    );
                                }
                            }
                            for _ in 0..code_length {
                                self.skip();
                            }
                        }
                    } else {
                        self.read(&mut string);
                    }
                }
                self.cache(2)?;
            }
            self.cache(1)?;
            if self.check(quote) {
                break;
            }
            self.cache(1)?;
            while is_blank(self.cur()) || is_break(self.cur()) {
                if is_blank(self.cur()) {
                    if leading_blanks {
                        self.skip();
                    } else {
                        self.read(&mut whitespaces);
                    }
                } else {
                    self.cache(2)?;
                    if leading_blanks {
                        self.read_line(&mut trailing_breaks);
                    } else {
                        whitespaces.clear();
                        self.read_line(&mut leading_break);
                        leading_blanks = true;
                    }
                }
                self.cache(1)?;
            }
            if leading_blanks {
                if leading_break.starts_with('\n') {
                    if trailing_breaks.is_empty() {
                        string.push(' ');
                    } else {
                        string.push_str(&trailing_breaks);
                        trailing_breaks.clear();
                    }
                    leading_break.clear();
                } else {
                    string.push_str(&leading_break);
                    string.push_str(&trailing_breaks);
                    leading_break.clear();
                    trailing_breaks.clear();
                }
            } else {
                string.push_str(&whitespaces);
                whitespaces.clear();
            }
        }
        self.skip();
        let end_mark = self.mark;
        Ok(Token {
            data: TokenData::Scalar {
                value: string,
                style: if single {
                    ScalarStyle::SingleQuoted
                } else {
                    ScalarStyle::DoubleQuoted
                },
            },
            start_mark,
            end_mark,
        })
    }

    fn scan_plain_scalar(&mut self) -> Result<Token> {
        let mut string = String::new();
        let mut leading_break = String::new();
        let mut trailing_breaks = String::new();
        let mut whitespaces = String::new();
        let mut leading_blanks = false;
        let indent = i64::from(self.indent) + 1;
        let start_mark = self.mark;
        let mut end_mark = self.mark;
        loop {
            self.cache(4)?;
            if self.mark.column == 0
                && (self.check_at('-', 0) && self.check_at('-', 1) && self.check_at('-', 2)
                    || self.check_at('.', 0) && self.check_at('.', 1) && self.check_at('.', 2))
                && is_blankz(self.at(3))
            {
                break;
            }
            if self.check('#') {
                break;
            }
            while !is_blankz(self.cur()) {
                if self.flow_level != 0
                    && self.check(':')
                    && matches!(self.at(1), Some(',' | '?' | '[' | ']' | '{' | '}'))
                {
                    return self.scanner_error(
                        Some("while scanning a plain scalar"),
                        start_mark,
                        "found unexpected ':'",
                    );
                }
                if self.check(':') && is_blankz(self.at(1))
                    || self.flow_level != 0
                        && matches!(self.cur(), Some(',' | '[' | ']' | '{' | '}'))
                {
                    break;
                }
                if leading_blanks || !whitespaces.is_empty() {
                    if leading_blanks {
                        if leading_break.starts_with('\n') {
                            if trailing_breaks.is_empty() {
                                string.push(' ');
                            } else {
                                string.push_str(&trailing_breaks);
                                trailing_breaks.clear();
                            }
                            leading_break.clear();
                        } else {
                            string.push_str(&leading_break);
                            string.push_str(&trailing_breaks);
                            leading_break.clear();
                            trailing_breaks.clear();
                        }
                        leading_blanks = false;
                    } else {
                        string.push_str(&whitespaces);
                        whitespaces.clear();
                    }
                }
                self.read(&mut string);
                end_mark = self.mark;
                self.cache(2)?;
            }
            if !(is_blank(self.cur()) || is_break(self.cur())) {
                break;
            }
            self.cache(1)?;
            while is_blank(self.cur()) || is_break(self.cur()) {
                if is_blank(self.cur()) {
                    if leading_blanks && (self.mark.column as i64) < indent && is_tab(self.cur()) {
                        return self.scanner_error(
                            Some("while scanning a plain scalar"),
                            start_mark,
                            "found a tab character that violates indentation",
                        );
                    } else if !leading_blanks {
                        self.read(&mut whitespaces);
                    } else {
                        self.skip();
                    }
                } else {
                    self.cache(2)?;
                    if leading_blanks {
                        self.read_line(&mut trailing_breaks);
                    } else {
                        whitespaces.clear();
                        self.read_line(&mut leading_break);
                        leading_blanks = true;
                    }
                }
                self.cache(1)?;
            }
            if self.flow_level == 0 && (self.mark.column as i64) < indent {
                break;
            }
        }
        if leading_blanks {
            self.simple_key_allowed = true;
        }
        Ok(Token {
            data: TokenData::Scalar {
                value: string,
                style: ScalarStyle::Plain,
            },
            start_mark,
            end_mark,
        })
    }
}
