// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PAYLOADS, MIRRORED IN OUR OWN STRUCTS.
//!
//! Two methods carry the plane. `tools/list` is the CATALOGUE and `tools/call` is the DISPATCH, and
//! `initialize` is the handshake that must precede either. Everything here is hand-written against
//! the specification rather than generated from anyone's schema: a generated type would decide, on
//! our behalf and permanently, which members are optional, how a variant is spelled, and what gets
//! silently dropped.
//!
//! ## Reading a server is not the same as trusting it
//!
//! These readers refuse anything ambiguous, and the recurring theme is that an ambiguity here is a
//! ROUTING decision handed to the untrusted party. A page listing one tool name twice is the clearest
//! case: taking the first or the last means which tool a caller reaches depends on the order the
//! server chose to list them in.
//!
//! What they deliberately do NOT do is judge CONTENT. Descriptions and outputs are not read, ranked
//! or sanitized here: busbar never routes on a description (that is the bound-identity rule), and
//! markup-normalization is a hook's job, not core's.

use serde_json::{Map, Value};

/// The handshake.
pub(crate) const METHOD_INITIALIZE: &str = "initialize";
/// THE CATALOGUE.
pub(crate) const METHOD_CATALOGUE: &str = "tools/list";
/// THE DISPATCH.
pub(crate) const METHOD_DISPATCH: &str = "tools/call";
/// Sent once, after the handshake is accepted.
pub(crate) const NOTIFY_INITIALIZED: &str = "notifications/initialized";
/// The server's hint that its catalogue moved. A HINT: it is attacker-controllable, so it may
/// prompt a re-pull of the authoritative catalogue but never supplies its contents.
pub(crate) const NOTIFY_CATALOGUE_CHANGED: &str = "notifications/tools/list_changed";

/// The revision this implementation is written against.
pub(crate) const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

/// The revisions this implementation will speak, newest first. An unknown version is refused at the
/// handshake rather than tolerated: continuing would mean reading every later payload under rules
/// that may not be the ones the server is applying, and the resulting failure would present as a
/// data problem rather than as the version problem it is. Adding a revision here is additive.
pub(crate) const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &[LATEST_PROTOCOL_VERSION, "2025-03-26", "2024-11-05"];

/// Why a payload was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SpecError {
    /// The payload is not the shape the specification describes. Carries which member was wrong.
    Malformed(String),
    /// A tool with no usable name. A nameless tool cannot be namespaced, approved or dispatched.
    EmptyToolName,
    /// One page offered the same tool name twice.
    DuplicateTool(String),
    /// A tool's input schema is present but is not an object.
    SchemaNotAnObject(String),
    /// The server chose a protocol revision this implementation does not speak.
    UnsupportedProtocolVersion(String),
}

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecError::Malformed(what) => write!(f, "malformed payload: {what}"),
            SpecError::EmptyToolName => write!(f, "a tool has no name"),
            SpecError::DuplicateTool(name) => {
                write!(f, "the catalogue offers `{name}` more than once")
            }
            SpecError::SchemaNotAnObject(name) => {
                write!(f, "the input schema of `{name}` is not an object")
            }
            SpecError::UnsupportedProtocolVersion(v) => {
                write!(
                    f,
                    "server chose protocol version `{v}`, which busbar does not speak"
                )
            }
        }
    }
}

// Small readers, so every refusal is named the same way everywhere --------------------------------

fn as_object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, SpecError> {
    v.as_object()
        .ok_or_else(|| SpecError::Malformed(format!("{what} is not an object")))
}

fn required_str<'a>(
    m: &'a Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<&'a str, SpecError> {
    match m.get(key) {
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(SpecError::Malformed(format!(
            "{what}.{key} is not a string"
        ))),
        None => Err(SpecError::Malformed(format!("{what}.{key} is missing"))),
    }
}

/// An optional string. Absent and null both mean absent; anything else is a refusal, because a
/// member of the wrong type is a server saying something we did not understand.
fn optional_str(
    m: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<String>, SpecError> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(SpecError::Malformed(format!(
            "{what}.{key} is not a string"
        ))),
    }
}

// The catalogue -----------------------------------------------------------------------------------

/// ONE TOOL, as the server describes it.
///
/// The description is carried but is never an input to a routing decision: busbar routes on the
/// bound identity `(server, tool, schema digest)` and shows the description to an operator or a
/// model, which is a different thing entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolDefinition {
    pub(crate) name: String,
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    /// The argument schema. Required, and required to be an object: it is what a dispatch validates
    /// against and part of what the digest pins, so a non-object here is a pin on something that can
    /// never be checked.
    pub(crate) input_schema: Value,
    pub(crate) output_schema: Option<Value>,
    pub(crate) annotations: Option<Value>,
}

impl ToolDefinition {
    fn parse(v: &Value) -> Result<Self, SpecError> {
        let m = as_object(v, "tool")?;
        let name = required_str(m, "name", "tool")?.to_string();
        if name.is_empty() {
            return Err(SpecError::EmptyToolName);
        }
        let input_schema = m
            .get("inputSchema")
            .cloned()
            .ok_or_else(|| SpecError::Malformed(format!("tool `{name}`.inputSchema is missing")))?;
        if !input_schema.is_object() {
            return Err(SpecError::SchemaNotAnObject(name));
        }
        Ok(ToolDefinition {
            title: optional_str(m, "title", "tool")?,
            description: optional_str(m, "description", "tool")?,
            output_schema: m.get("outputSchema").cloned(),
            annotations: m.get("annotations").cloned(),
            name,
            input_schema,
        })
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), Value::from(self.name.clone()));
        if let Some(t) = &self.title {
            m.insert("title".into(), Value::from(t.clone()));
        }
        if let Some(d) = &self.description {
            m.insert("description".into(), Value::from(d.clone()));
        }
        m.insert("inputSchema".into(), self.input_schema.clone());
        if let Some(s) = &self.output_schema {
            m.insert("outputSchema".into(), s.clone());
        }
        if let Some(a) = &self.annotations {
            m.insert("annotations".into(), a.clone());
        }
        Value::Object(m)
    }
}

/// One page of a server's CATALOGUE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CataloguePage {
    pub(crate) tools: Vec<ToolDefinition>,
    pub(crate) next_cursor: Option<String>,
}

impl CataloguePage {
    pub(crate) fn parse(v: &Value) -> Result<Self, SpecError> {
        let m = as_object(v, "tools/list result")?;
        // A MISSING `tools` member and an EMPTY one are different claims, and only the second is a
        // server saying it has no tools. Defaulting the first to the second turns a malformed reply
        // into a plausible-looking empty catalogue nobody investigates.
        let list = match m.get("tools") {
            Some(Value::Array(a)) => a,
            Some(_) => {
                return Err(SpecError::Malformed(
                    "tools/list result.tools is not an array".into(),
                ))
            }
            None => {
                return Err(SpecError::Malformed(
                    "tools/list result.tools is missing".into(),
                ))
            }
        };
        let mut tools = Vec::with_capacity(list.len());
        for entry in list {
            let tool = ToolDefinition::parse(entry)?;
            if tools.iter().any(|t: &ToolDefinition| t.name == tool.name) {
                return Err(SpecError::DuplicateTool(tool.name));
            }
            tools.push(tool);
        }
        Ok(CataloguePage {
            tools,
            next_cursor: optional_str(m, "nextCursor", "tools/list result")?,
        })
    }

    /// The params for the next page, or `None` when this was the last one.
    pub(crate) fn next_params(&self) -> Option<Value> {
        self.next_cursor.as_ref().map(|c| {
            let mut m = Map::new();
            m.insert("cursor".into(), Value::from(c.clone()));
            Value::Object(m)
        })
    }
}

// Dispatch ----------------------------------------------------------------------------------------

/// The params of a DISPATCH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DispatchParams {
    pub(crate) name: String,
    pub(crate) arguments: Option<Value>,
}

impl DispatchParams {
    pub(crate) fn new(name: impl Into<String>, arguments: Option<Value>) -> Self {
        DispatchParams {
            name: name.into(),
            arguments,
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), Value::from(self.name.clone()));
        // Absent arguments stay absent. Inventing an empty object is a change to the request we were
        // asked to make, and a server is entitled to tell the two apart.
        if let Some(a) = &self.arguments {
            m.insert("arguments".into(), a.clone());
        }
        Value::Object(m)
    }
}

/// One block of a tool's output.
///
/// The `Other` arm exists so a content type a newer server invents is CARRIED rather than dropped:
/// silently discarding part of a tool's output would hide it from the caller and from the audit
/// record at the same time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ContentBlock {
    Text { text: String },
    Image { data: String, mime_type: String },
    Audio { data: String, mime_type: String },
    ResourceLink { uri: String, name: Option<String> },
    Resource { uri: String, raw: Value },
    Other { kind: String, raw: Value },
}

impl ContentBlock {
    fn parse(v: &Value) -> Result<Self, SpecError> {
        let m = as_object(v, "content block")?;
        let kind = required_str(m, "type", "content block")?.to_string();
        Ok(match kind.as_str() {
            "text" => ContentBlock::Text {
                text: required_str(m, "text", "text content")?.to_string(),
            },
            "image" => ContentBlock::Image {
                data: required_str(m, "data", "image content")?.to_string(),
                mime_type: required_str(m, "mimeType", "image content")?.to_string(),
            },
            "audio" => ContentBlock::Audio {
                data: required_str(m, "data", "audio content")?.to_string(),
                mime_type: required_str(m, "mimeType", "audio content")?.to_string(),
            },
            "resource_link" => ContentBlock::ResourceLink {
                uri: required_str(m, "uri", "resource link")?.to_string(),
                name: optional_str(m, "name", "resource link")?,
            },
            "resource" => {
                let inner = m.get("resource").ok_or_else(|| {
                    SpecError::Malformed("resource content.resource is missing".into())
                })?;
                let im = as_object(inner, "resource content.resource")?;
                ContentBlock::Resource {
                    uri: required_str(im, "uri", "resource content.resource")?.to_string(),
                    raw: inner.clone(),
                }
            }
            _ => ContentBlock::Other {
                kind,
                raw: v.clone(),
            },
        })
    }
}

/// The result of a DISPATCH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DispatchResult {
    pub(crate) content: Vec<ContentBlock>,
    pub(crate) structured_content: Option<Value>,
    /// The TOOL reporting that it failed. Deliberately distinct from a JSON-RPC error, which is the
    /// SERVER reporting that the call could not be made: collapsing the two loses the tool's own
    /// message, which is usually the only thing that says what went wrong.
    pub(crate) is_error: bool,
}

impl DispatchResult {
    pub(crate) fn parse(v: &Value) -> Result<Self, SpecError> {
        let m = as_object(v, "tools/call result")?;
        let list = match m.get("content") {
            Some(Value::Array(a)) => a,
            Some(_) => {
                return Err(SpecError::Malformed(
                    "tools/call result.content is not an array".into(),
                ))
            }
            None => {
                return Err(SpecError::Malformed(
                    "tools/call result.content is missing".into(),
                ))
            }
        };
        let content = list
            .iter()
            .map(ContentBlock::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let is_error = match m.get("isError") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => {
                return Err(SpecError::Malformed(
                    "tools/call result.isError is not a boolean".into(),
                ))
            }
        };
        Ok(DispatchResult {
            content,
            structured_content: m.get("structuredContent").cloned(),
            is_error,
        })
    }
}

// The handshake -----------------------------------------------------------------------------------

/// What busbar says about itself when opening a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InitializeParams {
    pub(crate) client_name: String,
    pub(crate) client_version: String,
}

impl InitializeParams {
    pub(crate) fn new(client_name: impl Into<String>, client_version: impl Into<String>) -> Self {
        InitializeParams {
            client_name: client_name.into(),
            client_version: client_version.into(),
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut info = Map::new();
        info.insert("name".into(), Value::from(self.client_name.clone()));
        info.insert("version".into(), Value::from(self.client_version.clone()));
        let mut m = Map::new();
        m.insert(
            "protocolVersion".into(),
            Value::from(LATEST_PROTOCOL_VERSION),
        );
        // An EMPTY capabilities object, and that is the deny-by-default posture stated on the wire:
        // busbar advertises no sampling, no elicitation and no roots, so a server has nothing to
        // ask us for. A grant, when an operator makes one, is what would add a member here.
        m.insert("capabilities".into(), Value::Object(Map::new()));
        m.insert("clientInfo".into(), Value::Object(info));
        Value::Object(m)
    }
}

/// What the server says back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InitializeResult {
    pub(crate) protocol_version: String,
    pub(crate) server_name: Option<String>,
    pub(crate) server_version: Option<String>,
    /// Whether the server says it will send `notifications/tools/list_changed`. A convenience for
    /// scheduling a re-pull, never a substitute for one: the notification is attacker-controllable,
    /// so the authoritative catalogue is always re-fetched and re-digested.
    pub(crate) offers_catalogue_change_notifications: bool,
    pub(crate) capabilities: Value,
}

impl InitializeResult {
    pub(crate) fn parse(v: &Value) -> Result<Self, SpecError> {
        let m = as_object(v, "initialize result")?;
        let protocol_version = required_str(m, "protocolVersion", "initialize result")?.to_string();
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&protocol_version.as_str()) {
            return Err(SpecError::UnsupportedProtocolVersion(protocol_version));
        }
        let capabilities = m.get("capabilities").cloned().unwrap_or(Value::Null);
        let offers_catalogue_change_notifications = capabilities
            .get("tools")
            .and_then(|t| t.get("listChanged"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let (server_name, server_version) = match m.get("serverInfo") {
            Some(Value::Object(info)) => (
                optional_str(info, "name", "serverInfo")?,
                optional_str(info, "version", "serverInfo")?,
            ),
            _ => (None, None),
        };
        Ok(InitializeResult {
            protocol_version,
            server_name,
            server_version,
            offers_catalogue_change_notifications,
            capabilities,
        })
    }
}

#[cfg(test)]
#[path = "tests/spec_tests.rs"]
mod spec_tests;
