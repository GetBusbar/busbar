# Architecture and request flow

Busbar runs between applications and their configured upstream services. It authenticates callers, applies access and budget controls, and decides where a request may go before dispatch. Console manages the deployment through the admin API; it does not carry application traffic.

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 260" role="img" aria-label="One governed path to your upstreams. Console uses the admin API; application traffic stays in the engine." style="width:100%;height:auto;font-family:ui-sans-serif,system-ui,sans-serif">
<title>One governed path to your upstreams</title><defs><marker id="arch-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#a3e635"/></marker></defs>
<rect width="960" height="260" rx="12" fill="#111a2e"/><text x="32" y="38" fill="#e6edf7" font-size="20" font-weight="700">One governed path to your upstreams</text>
<rect x="32.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="2"/>
<text x="130.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Applications</text>
<text x="130.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Native protocol</text>
<text x="130.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Caller credential</text>
<path d="M234.0 130 H258.0" stroke="#a3e635" stroke-width="2" marker-end="url(#arch-arrow)"/>
<rect x="265.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#a3e635" stroke-width="2"/>
<text x="363.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Admit + govern</text>
<text x="363.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Identity · grants</text>
<text x="363.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Budget · policy</text>
<path d="M467.0 130 H491.0" stroke="#a3e635" stroke-width="2" marker-end="url(#arch-arrow)"/>
<rect x="498.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="2"/>
<text x="596.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Dispatch</text>
<text x="596.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Plane routing</text>
<text x="596.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Upstream credential</text>
<path d="M700.0 130 H724.0" stroke="#a3e635" stroke-width="2" marker-end="url(#arch-arrow)"/>
<rect x="731.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="2"/>
<text x="829.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Record</text>
<text x="829.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Usage ledger</text>
<text x="829.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Allowed telemetry</text>
<text x="32" y="238" fill="#94a3b8" font-size="14">Console uses the admin API; application traffic stays in the engine.</text></svg>

## Follow one request

1. **Accept the protocol.** A listener and transport deliver the request to the matching plane: models, MCP tools, A2A agents, decisions, or streaming.
2. **Establish authority.** Authentication identifies the caller. Core applies the caller's grants, allowed destinations, and budget or rate limits.
3. **Apply policy.** Configured hooks receive only their permitted view. Gates can refuse, restrict, order, or rewrite within their contract. Required gates can fail closed.
4. **Choose and dispatch.** The plane supplies its eligible destinations. Routing and failure handling respect that plane's execution boundaries; accepted tool or agent work is not blindly replayed as though it were a model read.
5. **Return and record.** The client receives its protocol's response. Reported usage enters the ledger, and configured exporters receive their allowed telemetry.

See the [protocol map](protocols-overview.md), [hooks](hooks.md), [routing](routing.md), and [failover boundaries](failover.md) for each stage's detailed behavior.

## Planes and transports

A **plane** gives traffic its meaning. A **transport** moves the bytes. HTTP, WebSocket, and stdio do not by themselves determine whether a request is a model call, tool invocation, or agent task.

| Plane | Reference |
|---|---|
| Models | [Native model protocols and translation](protocols.md) |
| Tools | [MCP calls and approvals](mcp.md) |
| Agents | [A2A delegation](a2a.md) |
| Decisions | [Decision models and services](decisions.md) |
| Streaming | [Voice and realtime sessions](voice.md) |

For models, supported cross-protocol requests pass through a shared intermediate representation. Same-protocol and cross-protocol routes have different fidelity guarantees; the [protocol reference](protocols.md) names those boundaries.

## State and credentials

The configured store holds the records its implementation supports. The memory store is ephemeral; select a durable store when approvals, keys, and operational records must survive restart. Cluster deployments also need to account for which enforcement counters are local and which records are shared.

Caller credentials and upstream credentials have separate roles. Use destination-owned credentials where configured, and grant hooks and exporters only the fields they need. Native plugins run as trusted code inside the process; signature verification is not a sandbox.

See [security](security.md), [plugin trust](plugins.md), and [configuration](configuration.md).

## Management and operations

The admin API and Console manage configuration and operational state. A running engine continues serving if Console becomes unavailable. Field-specific apply results distinguish changes that are live from those requiring reload or restart.

Use [the admin API reference](admin-api.md) for mutations and [operations](operations.md) for listeners, TLS, health, readiness, and shutdown.
