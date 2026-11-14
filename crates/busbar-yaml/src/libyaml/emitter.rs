//! A memory-safe YAML emitter producing byte-identical output to libyaml.
//!
//! This is a port of the emitter of libyaml 0.2.5 (MIT License,
//! Copyright (c) 2006-2016 Kirill Simonov, Copyright (c) 2017-2020 Ingy döt
//! Net) by way of its c2rust translation unsafe-libyaml 0.2.11 (MIT License,
//! David Tolnay), restricted to the event subset that serde_yaml's serializer
//! produces, with the emitter configured exactly as serde_yaml configures it:
//!
//! * `yaml_emitter_initialize` defaults: best_indent 2, LN line breaks,
//!   not canonical;
//! * `yaml_emitter_set_unicode(true)`;
//! * `yaml_emitter_set_width(-1)`, which `yaml_emitter_emit_stream_start`
//!   turns into a best width of `INT_MAX`;
//! * a UTF-8 stream, implicit document start/end, no `%YAML`/`%TAG`
//!   directives, no anchors or aliases, collection styles always "any",
//!   and `plain_implicit = quoted_implicit = implicit = tag.is_none()`.
//!
//! Code paths that cannot be reached under that configuration are left out.
//! Each of them is listed where it would have been, so the port can be
//! compared against the original function by function:
//!
//! * Line folding (`column > best_width`) never fires: the column would have
//!   to exceed `INT_MAX`.
//! * Flow collections are only ever chosen for empty sequences and mappings,
//!   so the flow level is never non-zero while a node is being emitted and
//!   the non-empty flow states do not exist.
//! * Folded scalars, canonical output, BOM output, version and tag
//!   directives, anchors and aliases cannot be requested.

use std::collections::VecDeque;
use std::io;

/// An emitter failure: libyaml's emitter error, or the writer's. serde_yaml_ng's
/// `libyaml::emitter::Error`.
#[derive(Debug)]
pub(crate) enum Error {
    Libyaml(super::error::Error),
    Io(io::Error),
}

fn problem(text: &'static str) -> Error {
    Error::Libyaml(super::error::Error::emitter(text))
}

#[derive(Debug)]
pub(crate) enum Event<'a> {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Scalar(Scalar<'a>),
    SequenceStart(Sequence),
    SequenceEnd,
    MappingStart(Mapping),
    MappingEnd,
}

#[derive(Debug)]
pub(crate) struct Scalar<'a> {
    pub tag: Option<String>,
    pub value: &'a str,
    pub style: ScalarStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScalarStyle {
    Any,
    Plain,
    SingleQuoted,
    Literal,
}

#[derive(Debug)]
pub(crate) struct Sequence {
    pub tag: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Mapping {
    pub tag: Option<String>,
}

/// libyaml's OUTPUT_BUFFER_SIZE.
const BUFFER_SIZE: usize = 16384;

/// libyaml's default (and here fixed) best_indent.
const BEST_INDENT: i64 = 2;

/// The two default tag directives (`yaml_emitter_emit_document_start`),
/// in the order libyaml searches them.
const DEFAULT_TAG_DIRECTIVES: [(&[u8], &[u8]); 2] = [(b"!", b"!"), (b"!!", b"tag:yaml.org,2002:")];

/// The subset of `yaml_emitter_state_t` reachable from this API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    StreamStart,
    FirstDocumentStart,
    DocumentStart,
    DocumentContent,
    DocumentEnd,
    FlowSequenceFirstItem,
    FlowMappingFirstKey,
    BlockSequenceFirstItem,
    BlockSequenceItem,
    BlockMappingFirstKey,
    BlockMappingKey,
    BlockMappingSimpleValue,
    BlockMappingValue,
    End,
}

/// The emitter's own copy of an event (libyaml copies every event it is
/// given into its queue, see `yaml_*_event_initialize`).
#[derive(Debug)]
enum QueuedEvent {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Scalar {
        tag: Option<Vec<u8>>,
        value: Vec<u8>,
        style: ScalarStyle,
    },
    SequenceStart {
        tag: Option<Vec<u8>>,
    },
    SequenceEnd,
    MappingStart {
        tag: Option<Vec<u8>>,
    },
    MappingEnd,
}

impl QueuedEvent {
    fn from_event(event: Event) -> QueuedEvent {
        match event {
            Event::StreamStart => QueuedEvent::StreamStart,
            Event::StreamEnd => QueuedEvent::StreamEnd,
            Event::DocumentStart => QueuedEvent::DocumentStart,
            Event::DocumentEnd => QueuedEvent::DocumentEnd,
            Event::Scalar(scalar) => QueuedEvent::Scalar {
                tag: scalar.tag.map(c_string),
                value: scalar.value.as_bytes().to_vec(),
                style: scalar.style,
            },
            Event::SequenceStart(sequence) => QueuedEvent::SequenceStart {
                tag: sequence.tag.map(c_string),
            },
            Event::SequenceEnd => QueuedEvent::SequenceEnd,
            Event::MappingStart(mapping) => QueuedEvent::MappingStart {
                tag: mapping.tag.map(c_string),
            },
            Event::MappingEnd => QueuedEvent::MappingEnd,
        }
    }
}

/// serde_yaml hands tags to libyaml as NUL-terminated C strings, and libyaml
/// measures them with `strlen`, so a tag ends at its first NUL byte.
fn c_string(tag: String) -> Vec<u8> {
    let mut bytes = tag.into_bytes();
    if let Some(nul) = bytes.iter().position(|&b| b == 0) {
        bytes.truncate(nul);
    }
    bytes
}

/// `yaml_emitter_t.tag_data`.
#[derive(Debug, Default)]
struct TagData {
    handle: Option<&'static [u8]>,
    suffix: Option<Vec<u8>>,
}

impl TagData {
    fn len(&self) -> usize {
        self.handle.map_or(0, <[u8]>::len) + self.suffix.as_ref().map_or(0, Vec::len)
    }
}

/// The resolved scalar style (`yaml_scalar_style_t` minus "any" and folded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
}

/// `yaml_emitter_t.scalar_data`. `flow_plain_allowed` is not tracked: it is
/// only consulted at a non-zero flow level, which never holds a scalar.
#[derive(Debug, Clone, Copy, Default)]
struct ScalarData {
    length: usize,
    multiline: bool,
    block_plain_allowed: bool,
    single_quoted_allowed: bool,
    block_allowed: bool,
}

pub(crate) struct Emitter<W> {
    write: W,
    /// Pending output; flushed when nearly full, at document and stream end,
    /// and on `flush`.
    buffer: Vec<u8>,

    state: State,
    states: Vec<State>,
    events: VecDeque<QueuedEvent>,
    indents: Vec<i64>,
    /// Whether the default tag directives are installed (between
    /// DOCUMENT-START and DOCUMENT-END).
    tag_directives: bool,

    indent: i64,
    column: i64,
    whitespace: bool,
    indention: bool,
    open_ended: u8,

    mapping_context: bool,
    simple_key_context: bool,

    tag_data: TagData,
    scalar_data: ScalarData,
}

type Result<T = (), E = Error> = std::result::Result<T, E>;

impl<W: io::Write> Emitter<W> {
    /// `yaml_emitter_initialize` + `yaml_emitter_set_output` with serde_yaml's
    /// settings.
    pub fn new(write: W) -> Emitter<W> {
        Emitter {
            write,
            buffer: Vec::with_capacity(BUFFER_SIZE),
            state: State::StreamStart,
            states: Vec::new(),
            events: VecDeque::new(),
            indents: Vec::new(),
            tag_directives: false,
            indent: 0,
            column: 0,
            whitespace: false,
            indention: false,
            open_ended: 0,
            mapping_context: false,
            simple_key_context: false,
            tag_data: TagData::default(),
            scalar_data: ScalarData::default(),
        }
    }

    /// `yaml_emitter_emit`: queue the event, then process queued events for
    /// as long as enough lookahead is available. An event that fails stays
    /// at the head of the queue, as in libyaml.
    pub fn emit(&mut self, event: Event) -> Result {
        self.events.push_back(QueuedEvent::from_event(event));
        while !self.need_more_events() {
            let Some(event) = self.events.pop_front() else {
                break;
            };
            let result = self
                .analyze_event(&event)
                .and_then(|()| self.state_machine(&event));
            if let Err(err) = result {
                self.events.push_front(event);
                return Err(err);
            }
        }
        Ok(())
    }

    /// `yaml_emitter_flush`: hand the buffered output to the writer. On
    /// failure the buffered output is discarded, as in libyaml.
    pub fn flush(&mut self) -> Result {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let result = self.write.write_all(&self.buffer);
        self.buffer.clear();
        result.map_err(Error::Io)
    }

    /// Returns the writer. Buffered output that was not flushed is dropped.
    pub fn into_inner(self) -> W {
        self.write
    }

    // ---------------------------------------------------------------------
    // Event queue (yaml_emitter_need_more_events, yaml_emitter_check_empty_*)
    // ---------------------------------------------------------------------

    /// `yaml_emitter_need_more_events`: DOCUMENT-START needs one event of
    /// lookahead, SEQUENCE-START two and MAPPING-START three, unless the
    /// queued events already close the node.
    fn need_more_events(&self) -> bool {
        let Some(head) = self.events.front() else {
            return true;
        };
        let accumulate = match head {
            QueuedEvent::DocumentStart => 1,
            QueuedEvent::SequenceStart { .. } => 2,
            QueuedEvent::MappingStart { .. } => 3,
            _ => return false,
        };
        if self.events.len() > accumulate {
            return false;
        }
        let mut level: i64 = 0;
        for event in &self.events {
            match event {
                QueuedEvent::StreamStart
                | QueuedEvent::DocumentStart
                | QueuedEvent::SequenceStart { .. }
                | QueuedEvent::MappingStart { .. } => level += 1,
                QueuedEvent::StreamEnd
                | QueuedEvent::DocumentEnd
                | QueuedEvent::SequenceEnd
                | QueuedEvent::MappingEnd => level -= 1,
                QueuedEvent::Scalar { .. } => {}
            }
            if level == 0 {
                return false;
            }
        }
        true
    }

    /// `yaml_emitter_check_empty_sequence`. `event` is the queue head, which
    /// has been taken off the queue while it is processed.
    fn check_empty_sequence(&self, event: &QueuedEvent) -> bool {
        matches!(event, QueuedEvent::SequenceStart { .. })
            && matches!(self.events.front(), Some(QueuedEvent::SequenceEnd))
    }

    /// `yaml_emitter_check_empty_mapping`.
    fn check_empty_mapping(&self, event: &QueuedEvent) -> bool {
        matches!(event, QueuedEvent::MappingStart { .. })
            && matches!(self.events.front(), Some(QueuedEvent::MappingEnd))
    }

    /// `yaml_emitter_check_simple_key`.
    fn check_simple_key(&self, event: &QueuedEvent) -> bool {
        let length = match event {
            QueuedEvent::Scalar { .. } => {
                if self.scalar_data.multiline {
                    return false;
                }
                self.tag_data.len() + self.scalar_data.length
            }
            QueuedEvent::SequenceStart { .. } => {
                if !self.check_empty_sequence(event) {
                    return false;
                }
                self.tag_data.len()
            }
            QueuedEvent::MappingStart { .. } => {
                if !self.check_empty_mapping(event) {
                    return false;
                }
                self.tag_data.len()
            }
            _ => return false,
        };
        length <= 128
    }

    // ---------------------------------------------------------------------
    // State machine (yaml_emitter_state_machine and yaml_emitter_emit_*)
    // ---------------------------------------------------------------------

    fn pop_state(&mut self) -> State {
        // Every pop is paired with an earlier push; the fallback is never used.
        self.states.pop().unwrap_or(State::End)
    }

    fn pop_indent(&mut self) -> i64 {
        self.indents.pop().unwrap_or(-1)
    }

    /// `yaml_emitter_increase_indent`.
    fn increase_indent(&mut self, flow: bool, indentless: bool) {
        self.indents.push(self.indent);
        if self.indent < 0 {
            self.indent = if flow { BEST_INDENT } else { 0 };
        } else if !indentless {
            self.indent += BEST_INDENT;
        }
    }

    /// `yaml_emitter_state_machine`.
    fn state_machine(&mut self, event: &QueuedEvent) -> Result {
        match self.state {
            State::StreamStart => self.emit_stream_start(event),
            State::FirstDocumentStart => self.emit_document_start(event, true),
            State::DocumentStart => self.emit_document_start(event, false),
            State::DocumentContent => self.emit_document_content(event),
            State::DocumentEnd => self.emit_document_end(event),
            State::FlowSequenceFirstItem => self.emit_flow_sequence_first_item(event),
            State::FlowMappingFirstKey => self.emit_flow_mapping_first_key(event),
            State::BlockSequenceFirstItem => self.emit_block_sequence_item(event, true),
            State::BlockSequenceItem => self.emit_block_sequence_item(event, false),
            State::BlockMappingFirstKey => self.emit_block_mapping_key(event, true),
            State::BlockMappingKey => self.emit_block_mapping_key(event, false),
            State::BlockMappingSimpleValue => self.emit_block_mapping_value(event, true),
            State::BlockMappingValue => self.emit_block_mapping_value(event, false),
            State::End => Err(problem("expected nothing after STREAM-END")),
        }
    }

    /// `yaml_emitter_emit_stream_start`.
    fn emit_stream_start(&mut self, event: &QueuedEvent) -> Result {
        self.open_ended = 0;
        if let QueuedEvent::StreamStart = event {
            self.indent = -1;
            self.column = 0;
            self.whitespace = true;
            self.indention = true;
            self.state = State::FirstDocumentStart;
            return Ok(());
        }
        Err(problem("expected STREAM-START"))
    }

    /// `yaml_emitter_emit_document_start`. Documents are always implicit,
    /// but every document after the first gets an explicit `---`.
    fn emit_document_start(&mut self, event: &QueuedEvent, first: bool) -> Result {
        match event {
            QueuedEvent::DocumentStart => {
                self.tag_directives = true;
                let implicit = first;
                self.open_ended = 0;
                if !implicit {
                    self.write_indent()?;
                    self.write_indicator(b"---", true, false, false)?;
                }
                self.state = State::DocumentContent;
                self.open_ended = 0;
                Ok(())
            }
            QueuedEvent::StreamEnd => {
                if self.open_ended == 2 {
                    self.write_indicator(b"...", true, false, false)?;
                    self.open_ended = 0;
                    self.write_indent()?;
                }
                self.flush()?;
                self.state = State::End;
                Ok(())
            }
            _ => Err(problem("expected DOCUMENT-START or STREAM-END")),
        }
    }

    /// `yaml_emitter_emit_document_content`.
    fn emit_document_content(&mut self, event: &QueuedEvent) -> Result {
        self.states.push(State::DocumentEnd);
        self.emit_node(event, false, false)
    }

    /// `yaml_emitter_emit_document_end` (implicit end: no `...`).
    fn emit_document_end(&mut self, event: &QueuedEvent) -> Result {
        if let QueuedEvent::DocumentEnd = event {
            self.write_indent()?;
            if self.open_ended == 0 {
                self.open_ended = 1;
            }
            self.flush()?;
            self.state = State::DocumentStart;
            self.tag_directives = false;
            return Ok(());
        }
        Err(problem("expected DOCUMENT-END"))
    }

    /// `yaml_emitter_emit_flow_sequence_item` with `first = true`. Flow style
    /// is only selected for an empty sequence, so the event here is always
    /// the SEQUENCE-END that `yaml_emitter_check_empty_sequence` saw.
    fn emit_flow_sequence_first_item(&mut self, event: &QueuedEvent) -> Result {
        self.write_indicator(b"[", true, true, false)?;
        self.increase_indent(true, false);
        if let QueuedEvent::SequenceEnd = event {
            self.indent = self.pop_indent();
            self.write_indicator(b"]", false, false, false)?;
            self.state = self.pop_state();
            return Ok(());
        }
        Err(problem("expected SEQUENCE-END"))
    }

    /// `yaml_emitter_emit_flow_mapping_key` with `first = true`; see
    /// `emit_flow_sequence_first_item`.
    fn emit_flow_mapping_first_key(&mut self, event: &QueuedEvent) -> Result {
        self.write_indicator(b"{", true, true, false)?;
        self.increase_indent(true, false);
        if let QueuedEvent::MappingEnd = event {
            self.indent = self.pop_indent();
            self.write_indicator(b"}", false, false, false)?;
            self.state = self.pop_state();
            return Ok(());
        }
        Err(problem("expected MAPPING-END"))
    }

    /// `yaml_emitter_emit_block_sequence_item`. A sequence that is a mapping
    /// value is not indented relative to its key (`key:\n- a`).
    fn emit_block_sequence_item(&mut self, event: &QueuedEvent, first: bool) -> Result {
        if first {
            let indentless = self.mapping_context && !self.indention;
            self.increase_indent(false, indentless);
        }
        if let QueuedEvent::SequenceEnd = event {
            self.indent = self.pop_indent();
            self.state = self.pop_state();
            return Ok(());
        }
        self.write_indent()?;
        self.write_indicator(b"-", true, false, true)?;
        self.states.push(State::BlockSequenceItem);
        self.emit_node(event, false, false)
    }

    /// `yaml_emitter_emit_block_mapping_key`.
    fn emit_block_mapping_key(&mut self, event: &QueuedEvent, first: bool) -> Result {
        if first {
            self.increase_indent(false, false);
        }
        if let QueuedEvent::MappingEnd = event {
            self.indent = self.pop_indent();
            self.state = self.pop_state();
            return Ok(());
        }
        self.write_indent()?;
        if self.check_simple_key(event) {
            self.states.push(State::BlockMappingSimpleValue);
            self.emit_node(event, true, true)
        } else {
            self.write_indicator(b"?", true, false, true)?;
            self.states.push(State::BlockMappingValue);
            self.emit_node(event, true, false)
        }
    }

    /// `yaml_emitter_emit_block_mapping_value`.
    fn emit_block_mapping_value(&mut self, event: &QueuedEvent, simple: bool) -> Result {
        if simple {
            self.write_indicator(b":", false, false, false)?;
        } else {
            self.write_indent()?;
            self.write_indicator(b":", true, false, true)?;
        }
        self.states.push(State::BlockMappingKey);
        self.emit_node(event, true, false)
    }

    /// `yaml_emitter_emit_node`. The root and sequence contexts are recorded
    /// by libyaml but never consulted, so only these two are kept.
    fn emit_node(&mut self, event: &QueuedEvent, mapping: bool, simple_key: bool) -> Result {
        self.mapping_context = mapping;
        self.simple_key_context = simple_key;
        match event {
            QueuedEvent::Scalar { value, style, .. } => self.emit_scalar(value, *style),
            QueuedEvent::SequenceStart { .. } => self.emit_sequence_start(event),
            QueuedEvent::MappingStart { .. } => self.emit_mapping_start(event),
            _ => Err(problem(
                "expected SCALAR, SEQUENCE-START, MAPPING-START, or ALIAS",
            )),
        }
    }

    /// `yaml_emitter_emit_scalar`.
    fn emit_scalar(&mut self, value: &[u8], style: ScalarStyle) -> Result {
        let style = self.select_scalar_style(style);
        self.process_tag()?;
        self.increase_indent(true, false);
        self.process_scalar(value, style)?;
        self.indent = self.pop_indent();
        self.state = self.pop_state();
        Ok(())
    }

    /// `yaml_emitter_emit_sequence_start`.
    fn emit_sequence_start(&mut self, event: &QueuedEvent) -> Result {
        self.process_tag()?;
        self.state = if self.check_empty_sequence(event) {
            State::FlowSequenceFirstItem
        } else {
            State::BlockSequenceFirstItem
        };
        Ok(())
    }

    /// `yaml_emitter_emit_mapping_start`.
    fn emit_mapping_start(&mut self, event: &QueuedEvent) -> Result {
        self.process_tag()?;
        self.state = if self.check_empty_mapping(event) {
            State::FlowMappingFirstKey
        } else {
            State::BlockMappingFirstKey
        };
        Ok(())
    }

    /// `yaml_emitter_select_scalar_style`. The "neither tag nor implicit
    /// flags" error and the forced `!` handle need a tagless scalar that is
    /// not implicit, which serde_yaml never sends. The flow-level conditions
    /// are always false here.
    fn select_scalar_style(&self, requested: ScalarStyle) -> Style {
        let data = &self.scalar_data;
        let mut style = match requested {
            ScalarStyle::Any | ScalarStyle::Plain => Style::Plain,
            ScalarStyle::SingleQuoted => Style::SingleQuoted,
            ScalarStyle::Literal => Style::Literal,
        };
        if self.simple_key_context && data.multiline {
            style = Style::DoubleQuoted;
        }
        if style == Style::Plain {
            if !data.block_plain_allowed {
                style = Style::SingleQuoted;
            }
            if data.length == 0 && self.simple_key_context {
                style = Style::SingleQuoted;
            }
        }
        if style == Style::SingleQuoted && !data.single_quoted_allowed {
            style = Style::DoubleQuoted;
        }
        if style == Style::Literal && (!data.block_allowed || self.simple_key_context) {
            style = Style::DoubleQuoted;
        }
        style
    }

    /// `yaml_emitter_process_tag`.
    fn process_tag(&mut self) -> Result {
        let handle = self.tag_data.handle;
        let Some(suffix) = self.tag_data.suffix.take() else {
            if let Some(handle) = handle {
                self.write_tag_handle(handle)?;
            }
            return Ok(());
        };
        let result = self.write_tag(handle, &suffix);
        self.tag_data.suffix = Some(suffix);
        result
    }

    fn write_tag(&mut self, handle: Option<&'static [u8]>, suffix: &[u8]) -> Result {
        if let Some(handle) = handle {
            self.write_tag_handle(handle)?;
            self.write_tag_content(suffix, false)
        } else {
            self.write_indicator(b"!<", true, false, false)?;
            self.write_tag_content(suffix, false)?;
            self.write_indicator(b">", false, false, false)
        }
    }

    /// `yaml_emitter_process_scalar`.
    fn process_scalar(&mut self, value: &[u8], style: Style) -> Result {
        match style {
            Style::Plain => self.write_plain_scalar(value),
            Style::SingleQuoted => self.write_single_quoted_scalar(value),
            Style::DoubleQuoted => self.write_double_quoted_scalar(value),
            Style::Literal => self.write_literal_scalar(value),
        }
    }

    // ---------------------------------------------------------------------
    // Analysis (yaml_emitter_analyze_*)
    // ---------------------------------------------------------------------

    /// `yaml_emitter_analyze_event`.
    fn analyze_event(&mut self, event: &QueuedEvent) -> Result {
        self.tag_data = TagData::default();
        self.scalar_data.length = 0;
        match event {
            QueuedEvent::Scalar { tag, value, .. } => {
                if let Some(tag) = tag {
                    self.analyze_tag(tag)?;
                }
                self.analyze_scalar(value);
                Ok(())
            }
            QueuedEvent::SequenceStart { tag: Some(tag) }
            | QueuedEvent::MappingStart { tag: Some(tag) } => self.analyze_tag(tag),
            _ => Ok(()),
        }
    }

    /// `yaml_emitter_analyze_tag`: split the tag into a directive handle and
    /// suffix, or leave it whole for verbatim `!<...>` output.
    fn analyze_tag(&mut self, tag: &[u8]) -> Result {
        if tag.is_empty() {
            return Err(problem("tag value must not be empty"));
        }
        if self.tag_directives {
            for (handle, prefix) in DEFAULT_TAG_DIRECTIVES {
                if prefix.len() < tag.len() && tag.starts_with(prefix) {
                    self.tag_data.handle = Some(handle);
                    self.tag_data.suffix = tag.get(prefix.len()..).map(<[u8]>::to_vec);
                    return Ok(());
                }
            }
        }
        self.tag_data.suffix = Some(tag.to_vec());
        Ok(())
    }

    /// `yaml_emitter_analyze_scalar`.
    fn analyze_scalar(&mut self, value: &[u8]) {
        let length = value.len();
        self.scalar_data.length = length;
        if value.is_empty() {
            self.scalar_data.multiline = false;
            self.scalar_data.block_plain_allowed = true;
            self.scalar_data.single_quoted_allowed = true;
            self.scalar_data.block_allowed = false;
            return;
        }

        let mut block_indicators = false;
        let mut line_breaks = false;
        let mut special_characters = false;
        let mut leading_space = false;
        let mut leading_break = false;
        let mut trailing_space = false;
        let mut trailing_break = false;
        let mut break_space = false;
        let mut space_break = false;
        let mut previous_space = false;
        let mut previous_break = false;

        if value.starts_with(b"---") || value.starts_with(b"...") {
            block_indicators = true;
        }

        let mut preceded_by_whitespace = true;
        let mut followed_by_whitespace = is_blankz_at(value, width_at(value, 0));
        let mut i = 0;
        while i < length {
            let c = at(value, i);
            let char_width = width_at(value, i);
            if i == 0 {
                if matches!(
                    c,
                    b'#' | b','
                        | b'['
                        | b']'
                        | b'{'
                        | b'}'
                        | b'&'
                        | b'*'
                        | b'!'
                        | b'|'
                        | b'>'
                        | b'\''
                        | b'"'
                        | b'%'
                        | b'@'
                        | b'`'
                ) {
                    block_indicators = true;
                }
                if (c == b'?' || c == b':') && followed_by_whitespace {
                    block_indicators = true;
                }
                if c == b'-' && followed_by_whitespace {
                    block_indicators = true;
                }
            } else {
                if c == b':' && followed_by_whitespace {
                    block_indicators = true;
                }
                if c == b'#' && preceded_by_whitespace {
                    block_indicators = true;
                }
            }

            // With unicode output enabled, only non-printable characters
            // are special.
            if !is_printable_at(value, i) {
                special_characters = true;
            }
            if is_break_at(value, i) {
                line_breaks = true;
            }

            if c == b' ' {
                if i == 0 {
                    leading_space = true;
                }
                if i + char_width == length {
                    trailing_space = true;
                }
                if previous_break {
                    break_space = true;
                }
                previous_space = true;
                previous_break = false;
            } else if is_break_at(value, i) {
                if i == 0 {
                    leading_break = true;
                }
                if i + char_width == length {
                    trailing_break = true;
                }
                if previous_space {
                    space_break = true;
                }
                previous_space = false;
                previous_break = true;
            } else {
                previous_space = false;
                previous_break = false;
            }

            preceded_by_whitespace = is_blankz_at(value, i);
            i += char_width;
            if i != length {
                followed_by_whitespace = is_blankz_at(value, i + width_at(value, i));
            }
        }

        let data = &mut self.scalar_data;
        data.multiline = line_breaks;
        data.block_plain_allowed = true;
        data.single_quoted_allowed = true;
        data.block_allowed = true;
        if leading_space || leading_break || trailing_space || trailing_break {
            data.block_plain_allowed = false;
        }
        if trailing_space {
            data.block_allowed = false;
        }
        if break_space {
            data.block_plain_allowed = false;
            data.single_quoted_allowed = false;
        }
        if space_break || special_characters {
            data.block_plain_allowed = false;
            data.single_quoted_allowed = false;
            data.block_allowed = false;
        }
        if line_breaks || block_indicators {
            data.block_plain_allowed = false;
        }
    }

    // ---------------------------------------------------------------------
    // Output primitives (FLUSH, PUT, PUT_BREAK, WRITE, WRITE_BREAK)
    // ---------------------------------------------------------------------

    /// `FLUSH`: make room for at least one more character.
    fn reserve(&mut self) -> Result {
        if self.buffer.len() + 5 < BUFFER_SIZE {
            Ok(())
        } else {
            self.flush()
        }
    }

    /// `PUT`.
    fn put(&mut self, byte: u8) -> Result {
        self.reserve()?;
        self.buffer.push(byte);
        self.column += 1;
        Ok(())
    }

    /// `PUT_BREAK` (line_break is always LN).
    fn put_break(&mut self) -> Result {
        self.reserve()?;
        self.buffer.push(b'\n');
        self.column = 0;
        Ok(())
    }

    /// `WRITE`: copy the character at `*pos` and advance past it.
    fn write_char(&mut self, string: &[u8], pos: &mut usize) -> Result {
        self.reserve()?;
        let end = (*pos + width_at(string, *pos)).min(string.len());
        if let Some(bytes) = string.get(*pos..end) {
            self.buffer.extend_from_slice(bytes);
        }
        *pos = end;
        self.column += 1;
        Ok(())
    }

    /// `WRITE_BREAK`: a `\n` is written as the configured line break, any
    /// other break character is copied as is.
    fn write_break(&mut self, string: &[u8], pos: &mut usize) -> Result {
        self.reserve()?;
        if at(string, *pos) == b'\n' {
            self.put_break()?;
            *pos += 1;
        } else {
            let end = (*pos + width_at(string, *pos)).min(string.len());
            if let Some(bytes) = string.get(*pos..end) {
                self.buffer.extend_from_slice(bytes);
            }
            *pos = end;
            self.column = 0;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Writers (yaml_emitter_write_*)
    // ---------------------------------------------------------------------

    /// `yaml_emitter_write_indent`.
    fn write_indent(&mut self) -> Result {
        let indent = self.indent.max(0);
        if !self.indention || self.column > indent || (self.column == indent && !self.whitespace) {
            self.put_break()?;
        }
        while self.column < indent {
            self.put(b' ')?;
        }
        self.whitespace = true;
        self.indention = true;
        Ok(())
    }

    /// `yaml_emitter_write_indicator`.
    fn write_indicator(
        &mut self,
        indicator: &[u8],
        need_whitespace: bool,
        is_whitespace: bool,
        is_indention: bool,
    ) -> Result {
        if need_whitespace && !self.whitespace {
            self.put(b' ')?;
        }
        let mut pos = 0;
        while pos < indicator.len() {
            self.write_char(indicator, &mut pos)?;
        }
        self.whitespace = is_whitespace;
        self.indention = self.indention && is_indention;
        Ok(())
    }

    /// `yaml_emitter_write_tag_handle`.
    fn write_tag_handle(&mut self, handle: &[u8]) -> Result {
        if !self.whitespace {
            self.put(b' ')?;
        }
        let mut pos = 0;
        while pos < handle.len() {
            self.write_char(handle, &mut pos)?;
        }
        self.whitespace = false;
        self.indention = false;
        Ok(())
    }

    /// `yaml_emitter_write_tag_content`: URI characters are copied, every
    /// byte of any other character is written as `%XX`.
    fn write_tag_content(&mut self, value: &[u8], need_whitespace: bool) -> Result {
        if need_whitespace && !self.whitespace {
            self.put(b' ')?;
        }
        let mut pos = 0;
        while pos < value.len() {
            let c = at(value, pos);
            if is_alpha(c) || b";/?:@&=+$,_.~*'()[]".contains(&c) {
                self.write_char(value, &mut pos)?;
            } else {
                for _ in 0..width_at(value, pos) {
                    let octet = at(value, pos);
                    pos += 1;
                    self.put(b'%')?;
                    self.put(hex_digit(octet >> 4))?;
                    self.put(hex_digit(octet & 0x0F))?;
                }
            }
        }
        self.whitespace = false;
        self.indention = false;
        Ok(())
    }

    /// `yaml_emitter_write_plain_scalar`. A plain scalar never contains line
    /// breaks (they make plain style unavailable) and never folds, so it is
    /// written as is.
    fn write_plain_scalar(&mut self, value: &[u8]) -> Result {
        if !self.whitespace && !value.is_empty() {
            self.put(b' ')?;
        }
        let mut pos = 0;
        while pos < value.len() {
            let is_space = at(value, pos) == b' ';
            self.write_char(value, &mut pos)?;
            if !is_space {
                self.indention = false;
            }
        }
        self.whitespace = false;
        self.indention = false;
        Ok(())
    }

    /// `yaml_emitter_write_single_quoted_scalar` (without folding).
    fn write_single_quoted_scalar(&mut self, value: &[u8]) -> Result {
        let mut breaks = false;
        self.write_indicator(b"'", true, false, false)?;
        let mut pos = 0;
        while pos < value.len() {
            if at(value, pos) == b' ' {
                self.write_char(value, &mut pos)?;
            } else if is_break_at(value, pos) {
                if !breaks && at(value, pos) == b'\n' {
                    self.put_break()?;
                }
                self.write_break(value, &mut pos)?;
                self.indention = true;
                breaks = true;
            } else {
                if breaks {
                    self.write_indent()?;
                }
                if at(value, pos) == b'\'' {
                    self.put(b'\'')?;
                }
                self.write_char(value, &mut pos)?;
                self.indention = false;
                breaks = false;
            }
        }
        if breaks {
            self.write_indent()?;
        }
        self.write_indicator(b"'", false, false, false)?;
        self.whitespace = false;
        self.indention = false;
        Ok(())
    }

    /// `yaml_emitter_write_double_quoted_scalar` (without folding).
    fn write_double_quoted_scalar(&mut self, value: &[u8]) -> Result {
        self.write_indicator(b"\"", true, false, false)?;
        let mut pos = 0;
        while pos < value.len() {
            let c = at(value, pos);
            let needs_escape = !is_printable_at(value, pos)
                || is_bom_at(value, pos)
                || is_break_at(value, pos)
                || c == b'"'
                || c == b'\\';
            if !needs_escape {
                self.write_char(value, &mut pos)?;
                continue;
            }

            let (code_point, char_width) = decode_at(value, pos);
            pos += char_width.max(1);
            self.put(b'\\')?;
            let short = match code_point {
                0x00 => Some(b'0'),
                0x07 => Some(b'a'),
                0x08 => Some(b'b'),
                0x09 => Some(b't'),
                0x0A => Some(b'n'),
                0x0B => Some(b'v'),
                0x0C => Some(b'f'),
                0x0D => Some(b'r'),
                0x1B => Some(b'e'),
                0x22 => Some(b'"'),
                0x5C => Some(b'\\'),
                0x85 => Some(b'N'),
                0xA0 => Some(b'_'),
                0x2028 => Some(b'L'),
                0x2029 => Some(b'P'),
                _ => None,
            };
            if let Some(escape) = short {
                self.put(escape)?;
                continue;
            }
            let (prefix, digits) = if code_point <= 0xFF {
                (b'x', 2)
            } else if code_point <= 0xFFFF {
                (b'u', 4)
            } else {
                (b'U', 8)
            };
            self.put(prefix)?;
            for k in (0..digits).rev() {
                // Each digit is masked to four bits, so the cast is lossless.
                self.put(hex_digit(((code_point >> (k * 4)) & 0x0F) as u8))?;
            }
        }
        self.write_indicator(b"\"", false, false, false)?;
        self.whitespace = false;
        self.indention = false;
        Ok(())
    }

    /// `yaml_emitter_write_block_scalar_hints`: indentation indicator when
    /// the content starts with a space or break, and the chomping indicator
    /// (`-` without a trailing break, `+` with more than one).
    fn write_block_scalar_hints(&mut self, value: &[u8]) -> Result {
        if at(value, 0) == b' ' || is_break_at(value, 0) {
            // b'0' + best_indent; BEST_INDENT is 2.
            self.write_indicator(b"2", false, false, false)?;
        }
        self.open_ended = 0;
        let mut chomp_hint: Option<&[u8]> = None;
        if value.is_empty() {
            chomp_hint = Some(b"-");
        } else {
            let last = previous_char_start(value, value.len());
            if !is_break_at(value, last) {
                chomp_hint = Some(b"-");
            } else if last == 0 {
                chomp_hint = Some(b"+");
                self.open_ended = 2;
            } else {
                let before_last = previous_char_start(value, last);
                if is_break_at(value, before_last) {
                    chomp_hint = Some(b"+");
                    self.open_ended = 2;
                }
            }
        }
        if let Some(chomp_hint) = chomp_hint {
            self.write_indicator(chomp_hint, false, false, false)?;
        }
        Ok(())
    }

    /// `yaml_emitter_write_literal_scalar`.
    fn write_literal_scalar(&mut self, value: &[u8]) -> Result {
        let mut breaks = true;
        self.write_indicator(b"|", true, false, false)?;
        self.write_block_scalar_hints(value)?;
        self.put_break()?;
        self.indention = true;
        self.whitespace = true;
        let mut pos = 0;
        while pos < value.len() {
            if is_break_at(value, pos) {
                self.write_break(value, &mut pos)?;
                self.indention = true;
                breaks = true;
            } else {
                if breaks {
                    self.write_indent()?;
                }
                self.write_char(value, &mut pos)?;
                self.indention = false;
                breaks = false;
            }
        }
        Ok(())
    }
}

// -------------------------------------------------------------------------
// Character classes (macros.rs). libyaml's strings carry a NUL terminator and
// its macros may look one byte past the end; `at` reproduces that by reading
// 0 beyond the end.
// -------------------------------------------------------------------------

fn at(string: &[u8], pos: usize) -> u8 {
    string.get(pos).copied().unwrap_or(0)
}

/// `WIDTH_AT`. Returns 1 rather than 0 for a stray continuation byte so that
/// scanning always advances; valid UTF-8 never needs this.
fn width_at(string: &[u8], pos: usize) -> usize {
    let octet = at(string, pos);
    if octet & 0x80 == 0x00 {
        1
    } else if octet & 0xE0 == 0xC0 {
        2
    } else if octet & 0xF0 == 0xE0 {
        3
    } else if octet & 0xF8 == 0xF0 {
        4
    } else {
        1
    }
}

/// Decode the UTF-8 character at `pos` the way
/// `yaml_emitter_write_double_quoted_scalar` does.
fn decode_at(string: &[u8], pos: usize) -> (u32, usize) {
    let octet = at(string, pos);
    let (width, mut value) = if octet & 0x80 == 0 {
        (1, u32::from(octet & 0x7F))
    } else if octet & 0xE0 == 0xC0 {
        (2, u32::from(octet & 0x1F))
    } else if octet & 0xF0 == 0xE0 {
        (3, u32::from(octet & 0x0F))
    } else if octet & 0xF8 == 0xF0 {
        (4, u32::from(octet & 0x07))
    } else {
        (0, 0)
    };
    for k in 1..width {
        value = (value << 6) | u32::from(at(string, pos + k) & 0x3F);
    }
    (value, width)
}

/// Step back from `pos` to the start of the previous UTF-8 character.
fn previous_char_start(string: &[u8], mut pos: usize) -> usize {
    while pos > 0 {
        pos -= 1;
        if at(string, pos) & 0xC0 != 0x80 {
            break;
        }
    }
    pos
}

fn hex_digit(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'A' + nibble - 10
    }
}

/// `IS_ALPHA`.
fn is_alpha(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// `IS_PRINTABLE` (on UTF-8 bytes).
fn is_printable_at(string: &[u8], pos: usize) -> bool {
    match at(string, pos) {
        0x0A | 0x20..=0x7E => true,
        // U+00A0 ... U+00BF
        0xC2 => matches!(at(string, pos + 1), 0xA0..=0xBF),
        // U+00C0 ... U+CFFF
        0xC3..=0xEC => true,
        // U+D000 ... U+D7FF
        0xED => at(string, pos + 1) <= 0x9F,
        // U+E000 ... U+EFFF
        0xEE => true,
        // U+F000 ... U+FFFD, except U+FEFF, U+FFFE and U+FFFF
        0xEF => match at(string, pos + 1) {
            0xBB => at(string, pos + 2) != 0xBF,
            0xBF => !matches!(at(string, pos + 2), 0xBE | 0xBF),
            _ => true,
        },
        // U+10000 ... U+10FFFF
        0xF0..=0xF4 => true,
        _ => false,
    }
}

/// `IS_BOM`.
fn is_bom_at(string: &[u8], pos: usize) -> bool {
    at(string, pos) == 0xEF && at(string, pos + 1) == 0xBB && at(string, pos + 2) == 0xBF
}

/// `IS_BREAK_AT`: CR, LF, NEL (U+0085), LS (U+2028), PS (U+2029).
fn is_break_at(string: &[u8], pos: usize) -> bool {
    match at(string, pos) {
        b'\r' | b'\n' => true,
        0xC2 => at(string, pos + 1) == 0x85,
        0xE2 => at(string, pos + 1) == 0x80 && matches!(at(string, pos + 2), 0xA8 | 0xA9),
        _ => false,
    }
}

/// `IS_BLANKZ_AT`: space, tab, break or NUL (including the terminator).
fn is_blankz_at(string: &[u8], pos: usize) -> bool {
    matches!(at(string, pos), b' ' | b'\t' | 0) || is_break_at(string, pos)
}
