//! The event parser: a memory-safe port of libyaml 0.2.5's `parser.c` (via unsafe-libyaml 0.2.11),
//! exposing the same `Parser`/`Event` interface serde_yaml_ng 0.10 built over libyaml
//! (`src/libyaml/parser.rs` there), so the deserializer above it is unchanged.

use super::error::{Error, Mark, Result};
use super::scanner::{Scanner, Token, TokenData};
use super::tag::{debug_lossy, Tag};
use std::borrow::Cow;
use std::fmt::{self, Debug};

#[derive(Debug)]
pub(crate) enum Event<'input> {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias(Anchor),
    Scalar(Scalar<'input>),
    SequenceStart(SequenceStart),
    SequenceEnd,
    MappingStart(MappingStart),
    MappingEnd,
}

pub(crate) struct Scalar<'input> {
    pub anchor: Option<Anchor>,
    pub tag: Option<Tag>,
    pub value: Box<[u8]>,
    pub style: ScalarStyle,
    pub repr: Option<&'input [u8]>,
}

#[derive(Debug)]
pub(crate) struct SequenceStart {
    pub anchor: Option<Anchor>,
    pub tag: Option<Tag>,
}

#[derive(Debug)]
pub(crate) struct MappingStart {
    pub anchor: Option<Anchor>,
    pub tag: Option<Tag>,
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Anchor(Box<[u8]>);

pub(crate) use super::scanner::ScalarStyle;

/// libyaml `yaml_parser_state_t`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum State {
    StreamStart,
    ImplicitDocumentStart,
    DocumentStart,
    DocumentContent,
    DocumentEnd,
    BlockNode,
    BlockSequenceFirstEntry,
    BlockSequenceEntry,
    IndentlessSequenceEntry,
    BlockMappingFirstKey,
    BlockMappingKey,
    BlockMappingValue,
    FlowSequenceFirstEntry,
    FlowSequenceEntry,
    FlowSequenceEntryMappingKey,
    FlowSequenceEntryMappingValue,
    FlowSequenceEntryMappingEnd,
    FlowMappingFirstKey,
    FlowMappingKey,
    FlowMappingValue,
    FlowMappingEmptyValue,
    End,
}

struct TagDirective {
    handle: Vec<u8>,
    prefix: Vec<u8>,
}

/// An event as libyaml produces it, before conversion to [`Event`].
enum Raw {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias(Vec<u8>),
    Scalar {
        anchor: Option<Vec<u8>>,
        tag: Option<Vec<u8>>,
        value: String,
        style: ScalarStyle,
    },
    SequenceStart {
        anchor: Option<Vec<u8>>,
        tag: Option<Vec<u8>>,
    },
    SequenceEnd,
    MappingStart {
        anchor: Option<Vec<u8>>,
        tag: Option<Vec<u8>>,
    },
    MappingEnd,
}

/// Boxed, as serde_yaml_ng's libyaml parser was, so the loader that holds it stays small.
pub(crate) struct Parser<'input>(Box<Inner<'input>>);

struct Inner<'input> {
    scanner: Scanner<'input>,
    /// The input when borrowed, for scalars' `repr` (libyaml's start..end source slice).
    borrowed: Option<&'input [u8]>,
    state: State,
    states: Vec<State>,
    marks: Vec<Mark>,
    tag_directives: Vec<TagDirective>,
    error: Option<Error>,
}

impl<'input> Parser<'input> {
    pub fn new(input: Cow<'input, [u8]>) -> Parser<'input> {
        let borrowed = match input {
            Cow::Borrowed(input) => Some(input),
            Cow::Owned(_) => None,
        };
        Parser(Box::new(Inner {
            scanner: Scanner::new(input),
            borrowed,
            state: State::StreamStart,
            states: Vec::new(),
            marks: Vec::new(),
            tag_directives: Vec::new(),
            error: None,
        }))
    }

    /// libyaml `yaml_parser_parse`: the next event and its start mark.
    pub fn next(&mut self) -> Result<(Event<'input>, Mark)> {
        self.0.next()
    }
}

impl<'input> Inner<'input> {
    fn next(&mut self) -> Result<(Event<'input>, Mark)> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        if self.scanner.stream_end_produced() || self.state == State::End {
            return Err(Error::internal(
                "the parser was asked for an event after the end of the stream",
            ));
        }
        match self.state_machine() {
            Ok((raw, start_mark, end_mark)) => {
                Ok((self.convert(raw, start_mark, end_mark), start_mark))
            }
            Err(error) => {
                self.error = Some(error.clone());
                Err(error)
            }
        }
    }

    fn convert(&self, raw: Raw, start_mark: Mark, end_mark: Mark) -> Event<'input> {
        let anchor = |a: Option<Vec<u8>>| a.map(|a| Anchor(a.into_boxed_slice()));
        let tag = |t: Option<Vec<u8>>| t.map(|t| Tag(t.into_boxed_slice()));
        match raw {
            Raw::StreamStart => Event::StreamStart,
            Raw::StreamEnd => Event::StreamEnd,
            Raw::DocumentStart => Event::DocumentStart,
            Raw::DocumentEnd => Event::DocumentEnd,
            Raw::Alias(a) => Event::Alias(Anchor(a.into_boxed_slice())),
            Raw::Scalar {
                anchor: a,
                tag: t,
                value,
                style,
            } => Event::Scalar(Scalar {
                anchor: anchor(a),
                tag: tag(t),
                value: value.into_bytes().into_boxed_slice(),
                style,
                repr: self.borrowed.and_then(|input| {
                    let start = usize::try_from(start_mark.index).ok()?;
                    let end = usize::try_from(end_mark.index).ok()?;
                    input.get(start..end)
                }),
            }),
            Raw::SequenceStart { anchor: a, tag: t } => Event::SequenceStart(SequenceStart {
                anchor: anchor(a),
                tag: tag(t),
            }),
            Raw::SequenceEnd => Event::SequenceEnd,
            Raw::MappingStart { anchor: a, tag: t } => Event::MappingStart(MappingStart {
                anchor: anchor(a),
                tag: tag(t),
            }),
            Raw::MappingEnd => Event::MappingEnd,
        }
    }

    fn pop_state(&mut self) -> State {
        self.states.pop().unwrap_or(State::End)
    }

    fn pop_mark(&mut self) -> Mark {
        self.marks.pop().unwrap_or(Mark::ZERO)
    }

    fn peek(&mut self) -> Result<&Token> {
        self.scanner.peek()
    }

    /// The type, start and end mark of the next token.
    fn peek_info(&mut self) -> Result<(TokenKind, Mark, Mark)> {
        let token = self.peek()?;
        Ok((TokenKind::of(&token.data), token.start_mark, token.end_mark))
    }

    fn skip_token(&mut self) -> Option<Token> {
        self.scanner.skip_token()
    }

    fn state_machine(&mut self) -> Result<(Raw, Mark, Mark)> {
        match self.state {
            State::StreamStart => self.parse_stream_start(),
            State::ImplicitDocumentStart => self.parse_document_start(true),
            State::DocumentStart => self.parse_document_start(false),
            State::DocumentContent => self.parse_document_content(),
            State::DocumentEnd => self.parse_document_end(),
            State::BlockNode => self.parse_node(true, false),
            State::BlockSequenceFirstEntry => self.parse_block_sequence_entry(true),
            State::BlockSequenceEntry => self.parse_block_sequence_entry(false),
            State::IndentlessSequenceEntry => self.parse_indentless_sequence_entry(),
            State::BlockMappingFirstKey => self.parse_block_mapping_key(true),
            State::BlockMappingKey => self.parse_block_mapping_key(false),
            State::BlockMappingValue => self.parse_block_mapping_value(),
            State::FlowSequenceFirstEntry => self.parse_flow_sequence_entry(true),
            State::FlowSequenceEntry => self.parse_flow_sequence_entry(false),
            State::FlowSequenceEntryMappingKey => self.parse_flow_sequence_entry_mapping_key(),
            State::FlowSequenceEntryMappingValue => self.parse_flow_sequence_entry_mapping_value(),
            State::FlowSequenceEntryMappingEnd => self.parse_flow_sequence_entry_mapping_end(),
            State::FlowMappingFirstKey => self.parse_flow_mapping_key(true),
            State::FlowMappingKey => self.parse_flow_mapping_key(false),
            State::FlowMappingValue => self.parse_flow_mapping_value(false),
            State::FlowMappingEmptyValue => self.parse_flow_mapping_value(true),
            State::End => Err(Error::internal("the parser reached its end state")),
        }
    }

    fn parse_stream_start(&mut self) -> Result<(Raw, Mark, Mark)> {
        let (kind, start_mark, _) = self.peek_info()?;
        if kind != TokenKind::StreamStart {
            return Err(Error::parser(
                "did not find expected <stream-start>",
                start_mark,
            ));
        }
        self.state = State::ImplicitDocumentStart;
        self.skip_token();
        Ok((Raw::StreamStart, start_mark, start_mark))
    }

    fn parse_document_start(&mut self, implicit: bool) -> Result<(Raw, Mark, Mark)> {
        let (mut kind, _, _) = self.peek_info()?;
        if !implicit {
            while kind == TokenKind::DocumentEnd {
                self.skip_token();
                kind = self.peek_info()?.0;
            }
        }
        let (kind, start_mark, _) = self.peek_info()?;
        if implicit
            && kind != TokenKind::VersionDirective
            && kind != TokenKind::TagDirective
            && kind != TokenKind::DocumentStart
            && kind != TokenKind::StreamEnd
        {
            self.process_directives()?;
            self.states.push(State::DocumentEnd);
            self.state = State::BlockNode;
            Ok((Raw::DocumentStart, start_mark, start_mark))
        } else if kind != TokenKind::StreamEnd {
            self.process_directives()?;
            let (kind, token_start, token_end) = self.peek_info()?;
            if kind != TokenKind::DocumentStart {
                return Err(Error::parser(
                    "did not find expected <document start>",
                    token_start,
                ));
            }
            self.states.push(State::DocumentEnd);
            self.state = State::DocumentContent;
            self.skip_token();
            Ok((Raw::DocumentStart, start_mark, token_end))
        } else {
            let (_, start_mark, end_mark) = self.peek_info()?;
            self.state = State::End;
            self.skip_token();
            Ok((Raw::StreamEnd, start_mark, end_mark))
        }
    }

    fn parse_document_content(&mut self) -> Result<(Raw, Mark, Mark)> {
        let (kind, start_mark, _) = self.peek_info()?;
        if matches!(
            kind,
            TokenKind::VersionDirective
                | TokenKind::TagDirective
                | TokenKind::DocumentStart
                | TokenKind::DocumentEnd
                | TokenKind::StreamEnd
        ) {
            self.state = self.pop_state();
            Ok(Self::empty_scalar(start_mark))
        } else {
            self.parse_node(true, false)
        }
    }

    fn parse_document_end(&mut self) -> Result<(Raw, Mark, Mark)> {
        let (kind, start_mark, token_end) = self.peek_info()?;
        let mut end_mark = start_mark;
        if kind == TokenKind::DocumentEnd {
            end_mark = token_end;
            self.skip_token();
        }
        self.tag_directives.clear();
        self.state = State::DocumentStart;
        Ok((Raw::DocumentEnd, start_mark, end_mark))
    }

    fn parse_node(&mut self, block: bool, indentless_sequence: bool) -> Result<(Raw, Mark, Mark)> {
        let (kind, token_start, token_end) = self.peek_info()?;
        if kind == TokenKind::Alias {
            self.state = self.pop_state();
            let value = match self.skip_token().map(|t| t.data) {
                Some(TokenData::Alias { value }) => value,
                _ => return Err(Error::internal("an alias token without a value")),
            };
            return Ok((Raw::Alias(value), token_start, token_end));
        }

        let mut anchor = None;
        let mut tag_handle_suffix: Option<(Vec<u8>, Vec<u8>)> = None;
        let mut start_mark = token_start;
        let mut end_mark = token_start;
        let mut tag_mark = Mark::ZERO;
        if kind == TokenKind::Anchor {
            start_mark = token_start;
            end_mark = token_end;
            if let Some(TokenData::Anchor { value }) = self.skip_token().map(|t| t.data) {
                anchor = Some(value);
            }
            let (kind, token_start, token_end) = self.peek_info()?;
            if kind == TokenKind::Tag {
                tag_mark = token_start;
                end_mark = token_end;
                if let Some(TokenData::Tag { handle, suffix }) = self.skip_token().map(|t| t.data) {
                    tag_handle_suffix = Some((handle, suffix));
                }
                self.peek()?;
            }
        } else if kind == TokenKind::Tag {
            tag_mark = token_start;
            start_mark = tag_mark;
            end_mark = token_end;
            if let Some(TokenData::Tag { handle, suffix }) = self.skip_token().map(|t| t.data) {
                tag_handle_suffix = Some((handle, suffix));
            }
            let (kind, _, token_end) = self.peek_info()?;
            if kind == TokenKind::Anchor {
                end_mark = token_end;
                if let Some(TokenData::Anchor { value }) = self.skip_token().map(|t| t.data) {
                    anchor = Some(value);
                }
                self.peek()?;
            }
        }

        let mut tag: Option<Vec<u8>> = None;
        if let Some((handle, suffix)) = tag_handle_suffix {
            if handle.is_empty() {
                tag = Some(suffix);
            } else {
                match self.tag_directives.iter().find(|d| d.handle == handle) {
                    Some(directive) => {
                        let mut resolved = directive.prefix.clone();
                        resolved.extend_from_slice(&suffix);
                        tag = Some(resolved);
                    }
                    None => {
                        return Err(Error::parser_context(
                            "while parsing a node",
                            start_mark,
                            "found undefined tag handle",
                            tag_mark,
                        ));
                    }
                }
            }
        }

        let (kind, token_start, token_end) = self.peek_info()?;
        if indentless_sequence && kind == TokenKind::BlockEntry {
            end_mark = token_end;
            self.state = State::IndentlessSequenceEntry;
            return Ok((Raw::SequenceStart { anchor, tag }, start_mark, end_mark));
        }
        match kind {
            TokenKind::Scalar => {
                end_mark = token_end;
                self.state = self.pop_state();
                let (value, style) = match self.skip_token().map(|t| t.data) {
                    Some(TokenData::Scalar { value, style }) => (value, style),
                    _ => return Err(Error::internal("a scalar token without a value")),
                };
                Ok((
                    Raw::Scalar {
                        anchor,
                        tag,
                        value,
                        style,
                    },
                    start_mark,
                    end_mark,
                ))
            }
            TokenKind::FlowSequenceStart => {
                end_mark = token_end;
                self.state = State::FlowSequenceFirstEntry;
                Ok((Raw::SequenceStart { anchor, tag }, start_mark, end_mark))
            }
            TokenKind::FlowMappingStart => {
                end_mark = token_end;
                self.state = State::FlowMappingFirstKey;
                Ok((Raw::MappingStart { anchor, tag }, start_mark, end_mark))
            }
            TokenKind::BlockSequenceStart if block => {
                end_mark = token_end;
                self.state = State::BlockSequenceFirstEntry;
                Ok((Raw::SequenceStart { anchor, tag }, start_mark, end_mark))
            }
            TokenKind::BlockMappingStart if block => {
                end_mark = token_end;
                self.state = State::BlockMappingFirstKey;
                Ok((Raw::MappingStart { anchor, tag }, start_mark, end_mark))
            }
            _ if anchor.is_some() || tag.is_some() => {
                self.state = self.pop_state();
                Ok((
                    Raw::Scalar {
                        anchor,
                        tag,
                        value: String::new(),
                        style: ScalarStyle::Plain,
                    },
                    start_mark,
                    end_mark,
                ))
            }
            _ => Err(Error::parser_context(
                if block {
                    "while parsing a block node"
                } else {
                    "while parsing a flow node"
                },
                start_mark,
                "did not find expected node content",
                token_start,
            )),
        }
    }

    fn parse_block_sequence_entry(&mut self, first: bool) -> Result<(Raw, Mark, Mark)> {
        if first {
            let (_, start_mark, _) = self.peek_info()?;
            self.marks.push(start_mark);
            self.skip_token();
        }
        let (kind, token_start, token_end) = self.peek_info()?;
        if kind == TokenKind::BlockEntry {
            let mark = token_end;
            self.skip_token();
            let (kind, _, _) = self.peek_info()?;
            if kind != TokenKind::BlockEntry && kind != TokenKind::BlockEnd {
                self.states.push(State::BlockSequenceEntry);
                self.parse_node(true, false)
            } else {
                self.state = State::BlockSequenceEntry;
                Ok(Self::empty_scalar(mark))
            }
        } else if kind == TokenKind::BlockEnd {
            self.state = self.pop_state();
            self.pop_mark();
            self.skip_token();
            Ok((Raw::SequenceEnd, token_start, token_end))
        } else {
            let context_mark = self.pop_mark();
            Err(Error::parser_context(
                "while parsing a block collection",
                context_mark,
                "did not find expected '-' indicator",
                token_start,
            ))
        }
    }

    fn parse_indentless_sequence_entry(&mut self) -> Result<(Raw, Mark, Mark)> {
        let (kind, token_start, token_end) = self.peek_info()?;
        if kind == TokenKind::BlockEntry {
            let mark = token_end;
            self.skip_token();
            let (kind, _, _) = self.peek_info()?;
            if !matches!(
                kind,
                TokenKind::BlockEntry | TokenKind::Key | TokenKind::Value | TokenKind::BlockEnd
            ) {
                self.states.push(State::IndentlessSequenceEntry);
                self.parse_node(true, false)
            } else {
                self.state = State::IndentlessSequenceEntry;
                Ok(Self::empty_scalar(mark))
            }
        } else {
            self.state = self.pop_state();
            Ok((Raw::SequenceEnd, token_start, token_start))
        }
    }

    fn parse_block_mapping_key(&mut self, first: bool) -> Result<(Raw, Mark, Mark)> {
        if first {
            let (_, start_mark, _) = self.peek_info()?;
            self.marks.push(start_mark);
            self.skip_token();
        }
        let (kind, token_start, token_end) = self.peek_info()?;
        if kind == TokenKind::Key {
            let mark = token_end;
            self.skip_token();
            let (kind, _, _) = self.peek_info()?;
            if !matches!(
                kind,
                TokenKind::Key | TokenKind::Value | TokenKind::BlockEnd
            ) {
                self.states.push(State::BlockMappingValue);
                self.parse_node(true, true)
            } else {
                self.state = State::BlockMappingValue;
                Ok(Self::empty_scalar(mark))
            }
        } else if kind == TokenKind::BlockEnd {
            self.state = self.pop_state();
            self.pop_mark();
            self.skip_token();
            Ok((Raw::MappingEnd, token_start, token_end))
        } else {
            let context_mark = self.pop_mark();
            Err(Error::parser_context(
                "while parsing a block mapping",
                context_mark,
                "did not find expected key",
                token_start,
            ))
        }
    }

    fn parse_block_mapping_value(&mut self) -> Result<(Raw, Mark, Mark)> {
        let (kind, token_start, token_end) = self.peek_info()?;
        if kind == TokenKind::Value {
            let mark = token_end;
            self.skip_token();
            let (kind, _, _) = self.peek_info()?;
            if !matches!(
                kind,
                TokenKind::Key | TokenKind::Value | TokenKind::BlockEnd
            ) {
                self.states.push(State::BlockMappingKey);
                self.parse_node(true, true)
            } else {
                self.state = State::BlockMappingKey;
                Ok(Self::empty_scalar(mark))
            }
        } else {
            self.state = State::BlockMappingKey;
            Ok(Self::empty_scalar(token_start))
        }
    }

    fn parse_flow_sequence_entry(&mut self, first: bool) -> Result<(Raw, Mark, Mark)> {
        if first {
            let (_, start_mark, _) = self.peek_info()?;
            self.marks.push(start_mark);
            self.skip_token();
        }
        let (mut kind, mut token_start, mut token_end) = self.peek_info()?;
        if kind != TokenKind::FlowSequenceEnd {
            if !first {
                if kind == TokenKind::FlowEntry {
                    self.skip_token();
                    (kind, token_start, token_end) = self.peek_info()?;
                } else {
                    let context_mark = self.pop_mark();
                    return Err(Error::parser_context(
                        "while parsing a flow sequence",
                        context_mark,
                        "did not find expected ',' or ']'",
                        token_start,
                    ));
                }
            }
            if kind == TokenKind::Key {
                self.state = State::FlowSequenceEntryMappingKey;
                self.skip_token();
                return Ok((
                    Raw::MappingStart {
                        anchor: None,
                        tag: None,
                    },
                    token_start,
                    token_end,
                ));
            } else if kind != TokenKind::FlowSequenceEnd {
                self.states.push(State::FlowSequenceEntry);
                return self.parse_node(false, false);
            }
        }
        self.state = self.pop_state();
        self.pop_mark();
        self.skip_token();
        Ok((Raw::SequenceEnd, token_start, token_end))
    }

    fn parse_flow_sequence_entry_mapping_key(&mut self) -> Result<(Raw, Mark, Mark)> {
        let (kind, _, token_end) = self.peek_info()?;
        if !matches!(
            kind,
            TokenKind::Value | TokenKind::FlowEntry | TokenKind::FlowSequenceEnd
        ) {
            self.states.push(State::FlowSequenceEntryMappingValue);
            self.parse_node(false, false)
        } else {
            let mark = token_end;
            self.skip_token();
            self.state = State::FlowSequenceEntryMappingValue;
            Ok(Self::empty_scalar(mark))
        }
    }

    fn parse_flow_sequence_entry_mapping_value(&mut self) -> Result<(Raw, Mark, Mark)> {
        let (mut kind, mut token_start, _) = self.peek_info()?;
        if kind == TokenKind::Value {
            self.skip_token();
            (kind, token_start, _) = self.peek_info()?;
            if kind != TokenKind::FlowEntry && kind != TokenKind::FlowSequenceEnd {
                self.states.push(State::FlowSequenceEntryMappingEnd);
                return self.parse_node(false, false);
            }
        }
        self.state = State::FlowSequenceEntryMappingEnd;
        Ok(Self::empty_scalar(token_start))
    }

    fn parse_flow_sequence_entry_mapping_end(&mut self) -> Result<(Raw, Mark, Mark)> {
        let (_, token_start, _) = self.peek_info()?;
        self.state = State::FlowSequenceEntry;
        Ok((Raw::MappingEnd, token_start, token_start))
    }

    fn parse_flow_mapping_key(&mut self, first: bool) -> Result<(Raw, Mark, Mark)> {
        if first {
            let (_, start_mark, _) = self.peek_info()?;
            self.marks.push(start_mark);
            self.skip_token();
        }
        let (mut kind, mut token_start, mut token_end) = self.peek_info()?;
        if kind != TokenKind::FlowMappingEnd {
            if !first {
                if kind == TokenKind::FlowEntry {
                    self.skip_token();
                    (kind, token_start, token_end) = self.peek_info()?;
                } else {
                    let context_mark = self.pop_mark();
                    return Err(Error::parser_context(
                        "while parsing a flow mapping",
                        context_mark,
                        "did not find expected ',' or '}'",
                        token_start,
                    ));
                }
            }
            if kind == TokenKind::Key {
                self.skip_token();
                let (kind, token_start, _) = self.peek_info()?;
                if !matches!(
                    kind,
                    TokenKind::Value | TokenKind::FlowEntry | TokenKind::FlowMappingEnd
                ) {
                    self.states.push(State::FlowMappingValue);
                    return self.parse_node(false, false);
                } else {
                    self.state = State::FlowMappingValue;
                    return Ok(Self::empty_scalar(token_start));
                }
            } else if kind != TokenKind::FlowMappingEnd {
                self.states.push(State::FlowMappingEmptyValue);
                return self.parse_node(false, false);
            }
        }
        self.state = self.pop_state();
        self.pop_mark();
        self.skip_token();
        Ok((Raw::MappingEnd, token_start, token_end))
    }

    fn parse_flow_mapping_value(&mut self, empty: bool) -> Result<(Raw, Mark, Mark)> {
        let (mut kind, mut token_start, _) = self.peek_info()?;
        if empty {
            self.state = State::FlowMappingKey;
            return Ok(Self::empty_scalar(token_start));
        }
        if kind == TokenKind::Value {
            self.skip_token();
            (kind, token_start, _) = self.peek_info()?;
            if kind != TokenKind::FlowEntry && kind != TokenKind::FlowMappingEnd {
                self.states.push(State::FlowMappingKey);
                return self.parse_node(false, false);
            }
        }
        self.state = State::FlowMappingKey;
        Ok(Self::empty_scalar(token_start))
    }

    fn empty_scalar(mark: Mark) -> (Raw, Mark, Mark) {
        (
            Raw::Scalar {
                anchor: None,
                tag: None,
                value: String::new(),
                style: ScalarStyle::Plain,
            },
            mark,
            mark,
        )
    }

    /// libyaml `yaml_parser_process_directives` (the version and tag directives are validated and
    /// the tag directives kept for this document; serde_yaml does not read them back).
    fn process_directives(&mut self) -> Result<()> {
        let mut has_version = false;
        loop {
            let (kind, start_mark, _) = self.peek_info()?;
            match kind {
                TokenKind::VersionDirective => {
                    let (major, minor) = match &self.peek()?.data {
                        TokenData::VersionDirective { major, minor } => (*major, *minor),
                        _ => (0, 0),
                    };
                    if has_version {
                        return Err(Error::parser("found duplicate %YAML directive", start_mark));
                    } else if major != 1 || minor != 1 && minor != 2 {
                        return Err(Error::parser(
                            "found incompatible YAML document",
                            start_mark,
                        ));
                    }
                    has_version = true;
                }
                TokenKind::TagDirective => {
                    let (handle, prefix) = match &self.peek()?.data {
                        TokenData::TagDirective { handle, prefix } => {
                            (handle.clone(), prefix.clone())
                        }
                        _ => (Vec::new(), Vec::new()),
                    };
                    self.append_tag_directive(TagDirective { handle, prefix }, false, start_mark)?;
                }
                _ => break,
            }
            self.skip_token();
        }
        let (_, mark, _) = self.peek_info()?;
        for (handle, prefix) in [
            (&b"!"[..], &b"!"[..]),
            (&b"!!"[..], &b"tag:yaml.org,2002:"[..]),
        ] {
            self.append_tag_directive(
                TagDirective {
                    handle: handle.to_vec(),
                    prefix: prefix.to_vec(),
                },
                true,
                mark,
            )?;
        }
        Ok(())
    }

    fn append_tag_directive(
        &mut self,
        value: TagDirective,
        allow_duplicates: bool,
        mark: Mark,
    ) -> Result<()> {
        if self.tag_directives.iter().any(|d| d.handle == value.handle) {
            if allow_duplicates {
                return Ok(());
            }
            return Err(Error::parser("found duplicate %TAG directive", mark));
        }
        self.tag_directives.push(value);
        Ok(())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum TokenKind {
    StreamStart,
    StreamEnd,
    VersionDirective,
    TagDirective,
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
    Alias,
    Anchor,
    Tag,
    Scalar,
}

impl TokenKind {
    fn of(data: &TokenData) -> TokenKind {
        match data {
            TokenData::StreamStart => TokenKind::StreamStart,
            TokenData::StreamEnd => TokenKind::StreamEnd,
            TokenData::VersionDirective { .. } => TokenKind::VersionDirective,
            TokenData::TagDirective { .. } => TokenKind::TagDirective,
            TokenData::DocumentStart => TokenKind::DocumentStart,
            TokenData::DocumentEnd => TokenKind::DocumentEnd,
            TokenData::BlockSequenceStart => TokenKind::BlockSequenceStart,
            TokenData::BlockMappingStart => TokenKind::BlockMappingStart,
            TokenData::BlockEnd => TokenKind::BlockEnd,
            TokenData::FlowSequenceStart => TokenKind::FlowSequenceStart,
            TokenData::FlowSequenceEnd => TokenKind::FlowSequenceEnd,
            TokenData::FlowMappingStart => TokenKind::FlowMappingStart,
            TokenData::FlowMappingEnd => TokenKind::FlowMappingEnd,
            TokenData::BlockEntry => TokenKind::BlockEntry,
            TokenData::FlowEntry => TokenKind::FlowEntry,
            TokenData::Key => TokenKind::Key,
            TokenData::Value => TokenKind::Value,
            TokenData::Alias { .. } => TokenKind::Alias,
            TokenData::Anchor { .. } => TokenKind::Anchor,
            TokenData::Tag { .. } => TokenKind::Tag,
            TokenData::Scalar { .. } => TokenKind::Scalar,
        }
    }
}

impl<'input> Debug for Scalar<'input> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        struct LossySlice<'a>(&'a [u8]);

        impl<'a> Debug for LossySlice<'a> {
            fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                debug_lossy(self.0, formatter)
            }
        }

        formatter
            .debug_struct("Scalar")
            .field("anchor", &self.anchor)
            .field("tag", &self.tag)
            .field("value", &LossySlice(&self.value))
            .field("style", &self.style)
            .finish()
    }
}

impl Debug for Anchor {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        debug_lossy(&self.0, formatter)
    }
}
