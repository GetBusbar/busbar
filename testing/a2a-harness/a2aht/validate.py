"""Structural validators for A2A objects.

These check only what the proto's REQUIRED annotations and SPEC 5.5/5.7
mandate. They deliberately do NOT check anything the spec merely suggests,
because a validator that enforces SHOULDs turns legal implementations red.
"""

from . import spec


def _problems_for(obj, required, label):
    out = []
    if not isinstance(obj, dict):
        return ["%s is not an object (got %s)" % (label, type(obj).__name__)]
    for field in required:
        if field not in obj or obj[field] in (None, ""):
            out.append("%s missing REQUIRED field %r" % (label, field))
    return out


def validate_agent_card(card):
    problems = _problems_for(card, spec.AGENT_CARD_REQUIRED, "AgentCard")
    if not isinstance(card, dict):
        return False, problems
    ifaces = card.get("supportedInterfaces")
    if isinstance(ifaces, list):
        for i, iface in enumerate(ifaces):
            problems += _problems_for(iface, spec.AGENT_INTERFACE_REQUIRED,
                                      "supportedInterfaces[%d]" % i)
    for i, skill in enumerate(card.get("skills") or []):
        problems += _problems_for(skill, spec.AGENT_SKILL_REQUIRED,
                                  "skills[%d]" % i)
    provider = card.get("provider")
    if provider is not None:
        problems += _problems_for(provider, spec.AGENT_PROVIDER_REQUIRED,
                                  "provider")
    for i, sig in enumerate(card.get("signatures") or []):
        problems += _problems_for(sig, spec.CARD_SIGNATURE_REQUIRED,
                                  "signatures[%d]" % i)
    return (not problems), problems


def validate_task(task):
    problems = _problems_for(task, spec.TASK_REQUIRED, "Task")
    if not isinstance(task, dict):
        return False, problems
    status = task.get("status")
    if isinstance(status, dict):
        problems += _problems_for(status, spec.TASK_STATUS_REQUIRED,
                                  "Task.status")
        state = status.get("state")
        if state is not None and state not in spec.TASK_STATES:
            problems.append(
                "Task.status.state %r is not a TaskState defined in the proto "
                "(%s)" % (state, ", ".join(spec.TASK_STATES)))
    for i, art in enumerate(task.get("artifacts") or []):
        problems += validate_artifact(art, "Task.artifacts[%d]" % i)
    for i, msg in enumerate(task.get("history") or []):
        problems += validate_message(msg, "Task.history[%d]" % i,
                                     require_message_id=False)
    return (not problems), problems


def validate_artifact(artifact, label="Artifact"):
    problems = _problems_for(artifact, spec.ARTIFACT_REQUIRED, label)
    if isinstance(artifact, dict):
        parts = artifact.get("parts")
        if isinstance(parts, list) and not parts:
            problems.append(
                "%s.parts is empty; PROTO Artifact: 'The content of the "
                "artifact. Must contain at least one part.'" % label)
        for i, part in enumerate(parts or []):
            problems += validate_part(part, "%s.parts[%d]" % (label, i))
    return problems


def validate_message(message, label="Message", require_message_id=True):
    required = list(spec.MESSAGE_REQUIRED)
    if not require_message_id:
        # See AMBIGUITIES.MESSAGE_ID_ON_AGENT_MESSAGES: the proto marks
        # message_id REQUIRED but the spec's own examples omit it on
        # agent-authored status messages.
        required = [f for f in required if f != "messageId"]
    problems = _problems_for(message, required, label)
    if isinstance(message, dict):
        role = message.get("role")
        if role is not None and role not in spec.ROLES:
            problems.append(
                "%s.role %r is not a Role defined in the proto (%s)"
                % (label, role, ", ".join(spec.ROLES)))
        for i, part in enumerate(message.get("parts") or []):
            problems += validate_part(part, "%s.parts[%d]" % (label, i))
    return problems


def validate_part(part, label="Part"):
    """PROTO Part is a oneof over text, raw, url and data."""
    if not isinstance(part, dict):
        return ["%s is not an object" % label]
    kinds = [k for k in ("text", "raw", "url", "data") if k in part]
    if not kinds:
        return ["%s sets none of the Part oneof members (text, raw, url, "
                "data)" % label]
    if len(kinds) > 1:
        return ["%s sets %d members of the Part oneof (%s); PROTO Part "
                "declares them as a oneof so exactly one may be set"
                % (label, len(kinds), kinds)]
    return []


def validate_stream_payload(payload, label="StreamResponse"):
    """PROTO StreamResponse oneof; SPEC 3.1.2 'exactly one per response'."""
    if not isinstance(payload, dict):
        return ["%s is not an object" % label]
    kinds = [k for k in spec.STREAM_PAYLOAD_KINDS if k in payload]
    problems = []
    if len(kinds) != 1:
        problems.append(
            "%s sets %d of the StreamResponse oneof members %s; SPEC 3.1.2 "
            "requires exactly one" % (label, len(kinds), kinds))
        return problems
    kind = kinds[0]
    if kind == "task":
        problems += validate_task(payload["task"])[1]
    elif kind == "message":
        problems += validate_message(payload["message"], "%s.message" % label,
                                     require_message_id=False)
    elif kind == "statusUpdate":
        problems += _problems_for(payload["statusUpdate"],
                                  spec.STATUS_UPDATE_REQUIRED,
                                  "%s.statusUpdate" % label)
    elif kind == "artifactUpdate":
        au = payload["artifactUpdate"]
        problems += _problems_for(au, spec.ARTIFACT_UPDATE_REQUIRED,
                                  "%s.artifactUpdate" % label)
        if isinstance(au, dict) and isinstance(au.get("artifact"), dict):
            problems += validate_artifact(au["artifact"],
                                          "%s.artifactUpdate.artifact" % label)
    return problems


def stream_payload_kind(payload):
    if not isinstance(payload, dict):
        return None
    kinds = [k for k in spec.STREAM_PAYLOAD_KINDS if k in payload]
    return kinds[0] if len(kinds) == 1 else None


def validate_timestamp(value, label="timestamp"):
    """SPEC 5.6.1: ISO 8601, UTC, 'Z' suffix, no other offsets."""
    problems = []
    if not isinstance(value, str):
        return ["%s is not a string" % label]
    if not value.endswith("Z"):
        problems.append(
            "%s is %r, which does not end in 'Z'. SPEC 5.6.1: 'Timestamps "
            "MUST NOT include timezone offsets other than Z (all times are "
            "UTC).'" % (label, value))
    if "T" not in value:
        problems.append("%s is %r, which is not ISO 8601 combined date and "
                        "time" % (label, value))
    return problems
