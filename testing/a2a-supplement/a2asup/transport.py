# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Three bindings, driven directly, with the credential under the caller's control.

WHY THIS DOES NOT REUSE THE TCK'S OWN TRANSPORT CLIENTS even though they exist and work: the whole
point of half these checks is to vary the CREDENTIAL -- absent, forged, principal A, principal B --
and to vary the `A2A-Version` header per request. The TCK's clients pin one version and carry no
credential at all, which is exactly right for the TCK's job and useless for this one.

The gRPC leg DOES use the specification's own generated stubs (`specification/generated/a2a_pb2`)
rather than a hand-rolled encoder, for the same reason `run-tck.sh` wires the publisher's suite
instead of writing a gRPC driver: hand-writing a wire fact is how a suite comes to test its own
encoder. Those stubs come from the pinned TCK checkout, so the proto this suite speaks and the
proto the official suite speaks are the same bytes at the same pin.
"""

from __future__ import annotations

import json

from dataclasses import dataclass
from typing import Any

import httpx

A2A_VERSION_HEADER = "A2A-Version"

# The method vocabularies. SPEC 9.1 gives 1.0 the PascalCase rpc names; SPEC 3.6.2 makes an absent
# or empty version 0.3, whose JSON-RPC names are the slash form. Both are listed because
# VER-SERVER-001 turns on the difference between them.
METHODS_1_0 = {
    "send_message": "SendMessage",
    "get_task": "GetTask",
    "list_tasks": "ListTasks",
    "cancel_task": "CancelTask",
    "subscribe_to_task": "SubscribeToTask",
    "create_push_config": "CreateTaskPushNotificationConfig",
    "get_push_config": "GetTaskPushNotificationConfig",
    "list_push_configs": "ListTaskPushNotificationConfigs",
    "delete_push_config": "DeleteTaskPushNotificationConfig",
    "get_extended_card": "GetExtendedAgentCard",
}
METHODS_0_3 = {
    "send_message": "message/send",
    "get_task": "tasks/get",
    "list_tasks": "tasks/list",
    "cancel_task": "tasks/cancel",
    "subscribe_to_task": "tasks/resubscribe",
    "create_push_config": "tasks/pushNotificationConfig/set",
    "get_push_config": "tasks/pushNotificationConfig/get",
    "list_push_configs": "tasks/pushNotificationConfig/list",
    "delete_push_config": "tasks/pushNotificationConfig/delete",
    "get_extended_card": "agent/getAuthenticatedExtendedCard",
}


@dataclass
class Reply:
    """One binding-neutral answer. `code` is the BINDING's own error code, unmapped."""

    ok: bool
    payload: Any = None
    code: Any = None
    message: str = ""
    http_status: int | None = None
    raw: Any = None

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return (
            f"Reply(ok={self.ok}, code={self.code!r}, http={self.http_status}, "
            f"message={self.message[:120]!r})"
        )


class JsonRpcBinding:
    name = "jsonrpc"

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        self.url = url
        self.timeout = timeout

    def call(
        self,
        op: str,
        params: dict | None = None,
        *,
        token: str | None = None,
        version: str | None = "1.0",
        extra_headers: dict[str, str] | None = None,
        method_override: str | None = None,
    ) -> Reply:
        vocab = METHODS_1_0 if (version is None or version.split(".")[0] != "0") else METHODS_0_3
        method = method_override or vocab[op]
        headers = {"content-type": "application/json"}
        if version is not None:
            headers[A2A_VERSION_HEADER] = version
        if token:
            headers["authorization"] = f"Bearer {token}"
        headers.update(extra_headers or {})
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        r = httpx.post(self.url, json=body, headers=headers, timeout=self.timeout)
        try:
            doc = r.json()
        except (json.JSONDecodeError, ValueError):
            return Reply(
                ok=False,
                code=f"http-{r.status_code}",
                message=r.text[:400],
                http_status=r.status_code,
                raw=r.text,
            )
        # A body that parses as JSON but is not an object -- a bare string challenge, say -- is
        # NOT a JSON-RPC envelope. Treating it as one and calling `.get` on it raises, and an
        # exception here would be indistinguishable from a transport failure by every caller.
        if not isinstance(doc, dict):
            return Reply(
                ok=r.status_code < 400,
                payload=doc,
                code=None if r.status_code < 400 else f"http-{r.status_code}",
                message="" if r.status_code < 400 else str(doc)[:400],
                http_status=r.status_code,
                raw=doc,
            )
        if "error" in doc:
            # `error` is REQUIRED to be an object by JSON-RPC 2.0, but implementations answer a
            # bare string often enough that assuming otherwise raises -- and a raise here is
            # indistinguishable from a transport failure to every caller above.
            err = doc["error"] if isinstance(doc["error"], dict) else {"message": doc["error"]}
            return Reply(
                ok=False,
                code=err.get("code", f"http-{r.status_code}" if r.status_code >= 400 else None),
                message=str(err.get("message", "")),
                http_status=r.status_code,
                raw=doc,
            )
        # A transport-level refusal that still returned JSON (an auth challenge, typically) is an
        # error even though it carries no JSON-RPC `error` member.
        if r.status_code >= 400:
            return Reply(
                ok=False,
                code=f"http-{r.status_code}",
                message=json.dumps(doc)[:400],
                http_status=r.status_code,
                raw=doc,
            )
        return Reply(
            ok=True,
            payload=doc.get("result") if isinstance(doc, dict) else doc,
            http_status=r.status_code,
            raw=doc,
        )


# SPEC 11.3. The REST body is the JSON-RPC `params` verbatim (SPEC 11.4), which is what makes the
# differential in `checks_bind.py` a comparison of the same request rather than of two requests.
REST_ROUTES: dict[str, tuple[str, str]] = {
    "send_message": ("POST", "/message:send"),
    "get_task": ("GET", "/tasks/{id}"),
    "list_tasks": ("GET", "/tasks"),
    "cancel_task": ("POST", "/tasks/{id}:cancel"),
    "subscribe_to_task": ("POST", "/tasks/{id}:subscribe"),
    "create_push_config": ("POST", "/tasks/{id}/pushNotificationConfigs"),
    "get_push_config": ("GET", "/tasks/{id}/pushNotificationConfigs/{config_id}"),
    "list_push_configs": ("GET", "/tasks/{id}/pushNotificationConfigs"),
    "delete_push_config": ("DELETE", "/tasks/{id}/pushNotificationConfigs/{config_id}"),
    "get_extended_card": ("GET", "/extendedAgentCard"),
}


class RestBinding:
    name = "http_json"

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout

    def call(
        self,
        op: str,
        params: dict | None = None,
        *,
        token: str | None = None,
        version: str | None = "1.0",
        extra_headers: dict[str, str] | None = None,
    ) -> Reply:
        verb, template = REST_ROUTES[op]
        params = dict(params or {})
        path = template
        for key in ("id", "config_id"):
            token_str = "{" + key + "}"
            if token_str in path:
                value = params.pop(key, None) or params.pop("name", None) or ""
                path = path.replace(token_str, str(value))
        headers = {"content-type": "application/json"}
        if version is not None:
            headers[A2A_VERSION_HEADER] = version
        if token:
            headers["authorization"] = f"Bearer {token}"
        headers.update(extra_headers or {})
        url = self.url + path
        if verb == "GET":
            r = httpx.get(url, params=_flatten(params), headers=headers, timeout=self.timeout)
        elif verb == "DELETE":
            r = httpx.delete(url, headers=headers, timeout=self.timeout)
        else:
            r = httpx.post(url, json=params, headers=headers, timeout=self.timeout)
        try:
            doc = r.json()
        except (json.JSONDecodeError, ValueError):
            doc = None
        if r.status_code >= 400:
            message = ""
            if isinstance(doc, dict):
                message = str(doc.get("message") or doc.get("error") or json.dumps(doc)[:400])
            return Reply(
                ok=False, code=r.status_code, message=message, http_status=r.status_code, raw=doc
            )
        return Reply(ok=True, payload=doc, http_status=r.status_code, raw=doc)


def _flatten(params: dict) -> dict:
    return {k: v for k, v in params.items() if isinstance(v, (str, int, float, bool))}


class GrpcBinding:
    """The gRPC binding, over the specification's own generated stubs.

    Constructed lazily so that a target whose card declares no gRPC interface never pays for the
    import -- but if the card DOES declare one and the stubs are missing, this raises. It does not
    degrade to a skip.
    """

    name = "grpc"

    def __init__(self, authority: str, timeout: float = 30.0) -> None:
        self.authority = authority
        self.timeout = timeout
        self._channel = None

    def _connect(self):
        if self._channel is None:
            import grpc  # noqa: PLC0415

            self._channel = grpc.insecure_channel(self.authority)
        return self._channel

    def close(self) -> None:
        if self._channel is not None:
            self._channel.close()
            self._channel = None

    def call(
        self,
        op: str,
        params: dict | None = None,
        *,
        token: str | None = None,
        version: str | None = "1.0",
        extra_headers: dict[str, str] | None = None,
    ) -> Reply:
        import grpc  # noqa: PLC0415

        from google.protobuf.json_format import MessageToDict, ParseDict  # noqa: PLC0415
        from specification.generated import a2a_pb2, a2a_pb2_grpc  # noqa: PLC0415

        rpc_name, request_type = _GRPC_OPS[op]
        stub = a2a_pb2_grpc.A2AServiceStub(self._connect())
        request = ParseDict(
            _grpc_params(op, dict(params or {})), getattr(a2a_pb2, request_type)()
        )
        metadata: list[tuple[str, str]] = []
        if version is not None:
            metadata.append((A2A_VERSION_HEADER.lower(), version))
        if token:
            metadata.append(("authorization", f"Bearer {token}"))
        for k, v in (extra_headers or {}).items():
            metadata.append((k.lower(), v))
        try:
            reply = getattr(stub, rpc_name)(
                request, timeout=self.timeout, metadata=tuple(metadata)
            )
        except grpc.RpcError as exc:
            return Reply(
                ok=False,
                code=exc.code().name,
                message=str(exc.details()),
                raw=exc,
            )
        return Reply(ok=True, payload=MessageToDict(reply), raw=reply)


# The request message for each rpc, READ OFF THE PINNED PROTO rather than guessed. Note that
# `CreateTaskPushNotificationConfig` takes a bare `TaskPushNotificationConfig` and not a
# `...Request` wrapper -- that asymmetry is the specification's, and copying it here is how this
# suite stays a reader of the proto rather than an author of one.
_GRPC_OPS: dict[str, tuple[str, str]] = {
    "send_message": ("SendMessage", "SendMessageRequest"),
    "get_task": ("GetTask", "GetTaskRequest"),
    "list_tasks": ("ListTasks", "ListTasksRequest"),
    "cancel_task": ("CancelTask", "CancelTaskRequest"),
    "subscribe_to_task": ("SubscribeToTask", "SubscribeToTaskRequest"),
    "create_push_config": ("CreateTaskPushNotificationConfig", "TaskPushNotificationConfig"),
    "get_push_config": (
        "GetTaskPushNotificationConfig",
        "GetTaskPushNotificationConfigRequest",
    ),
    "list_push_configs": (
        "ListTaskPushNotificationConfigs",
        "ListTaskPushNotificationConfigsRequest",
    ),
    "delete_push_config": (
        "DeleteTaskPushNotificationConfig",
        "DeleteTaskPushNotificationConfigRequest",
    ),
    "get_extended_card": ("GetExtendedAgentCard", "GetExtendedAgentCardRequest"),
}


def _grpc_params(op: str, params: dict) -> dict:
    """Rename the binding-neutral parameter names onto the proto's own field names.

    The proto spells the task identifier `id` on the task rpcs and `task_id` on the push-config
    rpcs, where the REST binding puts both in the path. That is a binding difference the
    specification itself defines, so translating it here is not smoothing over a divergence -- it
    is what makes the BIND-EQUIV differential compare the SAME request rather than two different
    ones. The mapping is transcribed from the pinned `a2a.proto`, and a field this suite invents
    would be rejected by the parser rather than silently accepted.
    """
    task_id = params.pop("id", None)
    config_id = params.pop("config_id", None)
    if op in {"get_task", "cancel_task", "subscribe_to_task"}:
        if task_id:
            params["id"] = task_id
    elif op in {"create_push_config", "list_push_configs"}:
        if task_id:
            params["taskId"] = task_id
    elif op in {"get_push_config", "delete_push_config"}:
        if task_id:
            params["taskId"] = task_id
        if config_id:
            params["id"] = config_id
    if op == "create_push_config":
        # The rpc takes a bare `TaskPushNotificationConfig` whose members are FLAT (`url`, `token`,
        # `authentication`), where the JSON bindings nest the same values under
        # `config.pushNotificationConfig`. Flattened here, from the pinned proto's own field list,
        # so the differential compares one request rather than two.
        inner = params.pop("config", None)
        if isinstance(inner, dict):
            inner = inner.get("pushNotificationConfig", inner)
        if isinstance(inner, dict):
            params.update(inner)
    return params
