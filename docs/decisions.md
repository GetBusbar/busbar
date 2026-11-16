# Decisions: models, services, and usage

The decisions plane gives applications a stable model name for a decision service. Busbar applies caller authorization and usage controls, routes the request to the configured service, and records the service's reported usage. The upstream service supplies the decision.

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 260" role="img" aria-label="Keep the model name; choose the decision service. The service supplies the decision. Busbar controls access, routing, and usage accounting." style="width:100%;height:auto;font-family:ui-sans-serif,system-ui,sans-serif">
<title>Keep the model name; choose the decision service</title><defs><marker id="decisions-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="#a3e635"/></marker></defs>
<rect width="960" height="260" rx="12" fill="#111a2e"/><text x="32" y="38" fill="#e6edf7" font-size="20" font-weight="700">Keep the model name; choose the decision service</text>
<rect x="32.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="2"/>
<text x="130.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Your application</text>
<text x="130.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Named decision model</text>
<text x="130.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Native request</text>
<path d="M234.0 130 H258.0" stroke="#a3e635" stroke-width="2" marker-end="url(#decisions-arrow)"/>
<rect x="265.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#a3e635" stroke-width="2"/>
<text x="363.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Busbar</text>
<text x="363.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Authorize and route</text>
<text x="363.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Map upstream model</text>
<path d="M467.0 130 H491.0" stroke="#a3e635" stroke-width="2" marker-end="url(#decisions-arrow)"/>
<rect x="498.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="2"/>
<text x="596.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Decision service</text>
<text x="596.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Compute the answer</text>
<text x="596.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Report usage</text>
<path d="M700.0 130 H724.0" stroke="#a3e635" stroke-width="2" marker-end="url(#decisions-arrow)"/>
<rect x="731.0" y="76" width="197.0" height="108" rx="10" fill="#1a2740" stroke="#2c3a52" stroke-width="2"/>
<text x="829.5" y="105" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700">Ledger</text>
<text x="829.5" y="133" text-anchor="middle" fill="#94a3b8" font-size="14">Decision units</text>
<text x="829.5" y="154" text-anchor="middle" fill="#94a3b8" font-size="14">Reported tokens</text>
<text x="32" y="238" fill="#94a3b8" font-size="14">The service supplies the decision. Busbar controls access, routing, and usage accounting.</text></svg>

## Endpoints

| Dialect | Endpoint | Reported decision units |
|---|---|---|
| `jev` | `POST /v1/systemone` | `usage.units` |
| `nanojev` | `POST /api/evaluate` | `execution.states` |

A dialect's endpoint is served only while a configured model uses it. No `decisions:` models means no active decision route.

## Configure a model

The model name the application uses maps to a provider connection and, optionally, an upstream model name:

```yaml
decisions:
  models:
    classifier:
      provider: decision-service
      upstream_model: classifier-v1
      protocol: jev
```

This is a section fragment: define `decision-service` under `providers:` with the service's base URL and credentials in the complete configuration. A model can inherit its protocol from its provider. Unknown keys and unsupported decision dialects are refused.

Busbar rewrites the top-level `model` to `upstream_model` when configured. Otherwise, native decision requests preserve the body, except for an explicitly bound request-stage hook rewrite. If the caller omits `model`, the request can select the sole model for that dialect; several matching models require an explicit name.

## Controls

| Setting | Purpose |
|---|---|
| `models` | Names callers may target and their provider mappings |
| `hooks` | Named hooks attached to decision requests |
| `catalog` | Description and release date for configured model names |
| `ingress` | Optional dedicated listener; otherwise use the data listener |
| `upstream_credentials` | Credential mode for outgoing requests |
| `rate_card`, `fees` | Prices for usage classes and per-request fees |

See [provider connections](providers.md), [hooks](hooks.md), and [per-plane rate cards](configuration.md#per-plane-rate-cards-toolsrate_card-agentsrate_card-streamsrate_card-decisionsrate_card).

## Usage and failures

The plane reports `decision`, `input_tokens`, and `output_tokens`. Valid fractional counts retain micro-unit precision. A successful response with a missing decision count uses a floor of one decision; malformed or negative counts are refused rather than replaced with a guessed value. Missing NanoJev counts also raise a usage warning.

The returned decision is the service's answer. Busbar does not claim to evaluate its quality or manage versions of the service's decision logic.

## Versioned text classification

`POST /busbar/decisions/v1/classify` provides a bounded, normalized classification response over configured decision models. Requests name a model, a short user/assistant message window, and 2–32 distinct tiers. Responses carry a label and only the confidence or probabilities the supported provider contract supplies; missing confidence remains missing.

Unsupported response shapes, unknown labels, invalid probabilities, and oversized responses fail normalization. Reported upstream usage still bills when normalization fails. Native `/v1/systemone` and `/api/evaluate` calls keep their separate relay behavior.
