# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""The subject under test: its card, its declared bindings, and the credentials handed to us.

EVERY BINDING IS READ OUT OF THE CARD, NEVER CONFIGURED. SPEC 5.2 makes the AgentCard the place an
agent declares what it speaks, and a suite that is TOLD which bindings to drive cannot notice that
the card lies about them. So the only thing this suite is given is one card URL; which bindings
exist, and at what addresses, is the subject's own answer.
"""

from __future__ import annotations

import json

from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from a2asup.transport import GrpcBinding, JsonRpcBinding, RestBinding

# SPEC 4.4 spells the binding discriminator `protocolBinding` with these values (see the section
# 8.5 sample card). Case is normalised because implementations differ on it and the difference is
# not what any of these requirements are about.
BINDING_NAMES = {
    "JSONRPC": "jsonrpc",
    "JSON-RPC": "jsonrpc",
    "HTTP+JSON": "http_json",
    "HTTP_JSON": "http_json",
    "REST": "http_json",
    "GRPC": "grpc",
}


@dataclass
class Interface:
    url: str
    binding: str
    version: str


@dataclass
class Target:
    """One A2A subject. `label` names it in every line of the report."""

    label: str
    card_url: str
    token: str | None = None
    """The credential for principal A. `None` means this target takes no credential."""
    token_b: str | None = None
    """A SECOND, DISTINCT authenticated principal. Required by AUTH-SCOPE-002/003, which cannot be
    decided with one identity: with a single principal, an implementation that scopes perfectly and
    one that scopes not at all are observationally identical."""
    upstream_record: str | None = None
    """Path to a JSONL recording of the requests the subject ORIGINATED upstream, if this target
    is a gateway with a recorder in front of its upstream. Required by VER-CLIENT-001."""

    card: dict = field(default_factory=dict)
    interfaces: list[Interface] = field(default_factory=list)

    def load(self) -> None:
        r = httpx.get(self.card_url, timeout=30.0, headers=self._headers())
        r.raise_for_status()
        self.card = r.json()
        self.interfaces = self._read_interfaces(self.card)
        if not self.interfaces:
            raise RuntimeError(
                f"{self.label}: the card at {self.card_url} declares no usable interface. "
                f"Every check below reads its endpoints out of the card (SPEC 5.2), so there is "
                f"nothing to drive. This is a hard stop and NOT a skip: a suite that shrugs here "
                f"reports the same green as one that ran. card={json.dumps(self.card)[:600]}"
            )

    def _headers(self) -> dict[str, str]:
        return {"authorization": f"Bearer {self.token}"} if self.token else {}

    @staticmethod
    def _read_interfaces(card: dict) -> list[Interface]:
        out: list[Interface] = []
        for entry in card.get("supportedInterfaces") or []:
            if not isinstance(entry, dict):
                continue
            raw = str(entry.get("protocolBinding") or entry.get("transport") or "").upper()
            name = BINDING_NAMES.get(raw)
            url = entry.get("url")
            if not name or not url:
                continue
            out.append(
                Interface(url=url, binding=name, version=str(entry.get("protocolVersion") or ""))
            )
        # SPEC 8.3 pre-1.0 spelling, accepted so that a target published against the older card
        # shape is DRIVEN rather than reported as having no bindings -- which would silently turn
        # every equivalence check into a non-answer.
        if not out and card.get("url"):
            legacy = BINDING_NAMES.get(str(card.get("preferredTransport") or "JSONRPC").upper())
            if legacy:
                out.append(Interface(url=card["url"], binding=legacy, version=""))
        return out

    def bindings(self) -> dict[str, object]:
        """One driver per DISTINCT binding the card declares, keyed by binding name."""
        made: dict[str, object] = {}
        for iface in self.interfaces:
            if iface.binding in made:
                continue
            if iface.binding == "jsonrpc":
                made[iface.binding] = JsonRpcBinding(iface.url)
            elif iface.binding == "http_json":
                made[iface.binding] = RestBinding(iface.url)
            elif iface.binding == "grpc":
                made[iface.binding] = GrpcBinding(_authority(iface.url))
        return made

    def versions_declared(self) -> list[str]:
        return sorted({i.version for i in self.interfaces if i.version})


def _authority(url: str) -> str:
    """`host:port` for a gRPC channel, from the URL the card publishes for that interface."""
    parsed = urlparse(url if "//" in url else f"//{url}")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host}:{port}"
