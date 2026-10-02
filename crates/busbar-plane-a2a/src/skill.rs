// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SKILL A REQUEST MATCHES on an agent's card (ARCHITECT ruling B2): busbar's own namespaced
//! annotation, `metadata["busbar/skill"]` on the answer. Moved from the served engine
//! (`busbar-a2a` `registry::judge` and `receive::shape_of`, which now read these), byte for byte.
//!
//! The fit is STRUCTURAL, never a score: an agent either can accept this shape of task or it
//! cannot. A request that names a skill matches the card's skill of that id under the skill's own
//! modes (the card's defaults where it declares none); one that names none matches no skill.

use serde_json::Value;

use crate::a2a::agent_card::AgentCard;

/// EVERY PLACE A2A SPELLS "the callback to call when this task moves", in both revisions: v0.3's
/// `pushNotificationConfig`, v1.0's `taskPushNotificationConfig`, flat or nested.
pub const CALLBACK_POINTERS: [&str; 3] = [
    "/params/configuration/pushNotificationConfig/url",
    "/params/configuration/taskPushNotificationConfig/url",
    "/params/configuration/taskPushNotificationConfig/pushNotificationConfig/url",
];

/// The CONFIG OBJECTS those three URLs sit in, in the same order, so the URL and the credential
/// beside it are read out of ONE object.
pub const CALLBACK_CONFIG_POINTERS: [&str; 3] = [
    "/params/configuration/pushNotificationConfig",
    "/params/configuration/taskPushNotificationConfig",
    "/params/configuration/taskPushNotificationConfig/pushNotificationConfig",
];

/// DOES THIS METHOD NAME ASK FOR A STREAM? Both eras of the name: v0.3's `message/stream` and
/// `tasks/resubscribe`, v1.0's `SendStreamingMessage` and `SubscribeToTask`.
#[must_use]
pub fn reads_as_stream(method: &str) -> bool {
    method.ends_with("/stream")
        || method == "tasks/resubscribe"
        || method == "SendStreamingMessage"
        || method == "SubscribeToTask"
}

/// THE SHAPE OF A TASK, as the fit is allowed to see it: typed metadata only, never prose.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskShape {
    /// The skill being asked for, by `id`. `None` means "any skill this agent declares".
    pub skill: Option<String>,
    /// The task needs a stream.
    pub requires_stream: bool,
    /// The task registers a push callback.
    pub requires_push_notifications: bool,
    /// MIME modes the caller will SEND.
    pub input_modes: Vec<String>,
    /// MIME modes the caller can ACCEPT back.
    pub output_modes: Vec<String>,
}

impl TaskShape {
    /// The shape an inbound envelope asks for. An envelope that names nothing constrains nothing.
    #[must_use]
    pub fn of(envelope: &Value) -> Self {
        let params = envelope.get("params");
        let cfg = params.and_then(|p| p.get("configuration"));
        TaskShape {
            skill: params
                .and_then(|p| p.get("metadata"))
                .and_then(|m| m.get("skill"))
                .and_then(Value::as_str)
                .map(str::to_string),
            requires_stream: envelope
                .get("method")
                .and_then(Value::as_str)
                .is_some_and(reads_as_stream),
            requires_push_notifications: CALLBACK_CONFIG_POINTERS
                .into_iter()
                .any(|p| envelope.pointer(p).is_some()),
            input_modes: Vec::new(),
            output_modes: cfg
                .and_then(|c| c.get("acceptedOutputModes"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// WHY A CARD DOES NOT FIT A SHAPE. The arms keep the engine's `registry::Excluded` names, whose
/// `Debug` rendering is the words its catalogue refusal carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unfit {
    /// The card declares no skill with the requested id.
    SkillNotDeclared(String),
    /// The card does not declare a capability the task requires.
    CapabilityNotDeclared(&'static str),
    /// The card accepts none of the modes the caller will send, or produces none it can accept.
    ModesIncompatible,
    /// The held card cannot be read.
    Unreadable(Unreadable),
}

/// Why a held card cannot be read (the engine's `card::CardError` arm a read can fail with).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unreadable {
    /// The document is not a card.
    NotAnObject,
}

/// THE FIT of a held card DOCUMENT to `shape`: [`judge`] over the card read.
///
/// # Errors
/// [`Unfit`]; [`Unfit::Unreadable`] for a document that is not a card.
pub fn fit(card: &Value, shape: &TaskShape) -> Result<Option<String>, Unfit> {
    let card =
        crate::a2a::agent_card::parse(card).ok_or(Unfit::Unreadable(Unreadable::NotAnObject))?;
    judge(&card, shape)
}

/// The status a request an agent's card does not fit is refused with.
pub const STATUS_UNFIT: u32 = 403;

/// THE REFUSAL of a request an agent's held card does not fit (the engine's catalogue exclusion):
/// `403`, `-32004`, no id, the exclusion's own name as the message.
#[must_use]
pub fn refusal(unfit: &Unfit) -> crate::arrival::Refusal {
    crate::arrival::Refusal {
        status: STATUS_UNFIT,
        id: None,
        code: crate::arrival::CODE_UNSUPPORTED_OPERATION,
        message: format!("{unfit:?}"),
    }
}

/// JUDGE WHETHER AN AGENT CARD FITS A TASK SHAPE: the matched skill id (`None` when the shape
/// names none), or why it does not fit.
///
/// # Errors
/// [`Unfit`].
pub fn judge(card: &AgentCard, shape: &TaskShape) -> Result<Option<String>, Unfit> {
    if shape.requires_stream && !card.capabilities.is_stream {
        return Err(Unfit::CapabilityNotDeclared("streaming"));
    }
    if shape.requires_push_notifications && !card.capabilities.push_notifications {
        return Err(Unfit::CapabilityNotDeclared("pushNotifications"));
    }
    if let Some(wanted) = &shape.skill {
        let skill = card
            .skills
            .iter()
            .find(|s| &s.id == wanted)
            .ok_or_else(|| Unfit::SkillNotDeclared(wanted.clone()))?;
        // A skill's own modes OVERRIDE the card defaults where it declares them.
        let inputs = pick(&skill.input_modes, &card.default_input_modes);
        let outputs = pick(&skill.output_modes, &card.default_output_modes);
        check_modes(shape, inputs, outputs)?;
        return Ok(Some(skill.id.clone()));
    }
    check_modes(shape, &card.default_input_modes, &card.default_output_modes)?;
    Ok(None)
}

fn pick<'a>(specific: &'a [String], fallback: &'a [String]) -> &'a [String] {
    if specific.is_empty() {
        fallback
    } else {
        specific
    }
}

/// The caller must be able to SEND something the agent accepts and RECEIVE something it produces;
/// a side that names no modes constrains nothing.
fn check_modes(
    shape: &TaskShape,
    agent_inputs: &[String],
    agent_outputs: &[String],
) -> Result<(), Unfit> {
    let compatible = |wanted: &[String], declared: &[String]| -> bool {
        wanted.is_empty() || declared.is_empty() || wanted.iter().any(|w| declared.contains(w))
    };
    if !compatible(&shape.input_modes, agent_inputs)
        || !compatible(&shape.output_modes, agent_outputs)
    {
        return Err(Unfit::ModesIncompatible);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/skill_tests.rs"]
mod tests;
