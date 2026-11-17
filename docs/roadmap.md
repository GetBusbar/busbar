# Roadmap

What Busbar is working toward, and what it has decided not to do. This page states direction, not
dates or support commitments. Nothing here is a claim that a feature has shipped: the
[changelog](../CHANGELOG.md) and the reference pages describe what a release contains, and the
[migration guide](migration-1.6.md) describes what changes from 1.5.5.

## In 1.6.0

1.6.0 is a drop-in upgrade for a 1.5.5 deployment: the first boot migrates the configuration and the
core's own records, and every difference an operator will see is listed in the
[migration guide](migration-1.6.md). Its scope also includes:

- Verifiable release assurance: signed releases, provenance and an SBOM per release, and
  verify-it-yourself commands ([verify a release](verify.md)).
- Rate and token limits enforced against the model a fallback actually selects, with per-attempt
  model accounting.
- Correlated diagnostics through logs and the authorized admin API and Console, without new
  diagnostic headers or body fields on client responses.
- Decisions on Gemini, a matrix of the major providers, and shared adapters for the agreed gaps.
- Model discovery from the caller's authorized inventory, with truthful capabilities, across the
  major clients (Codex, Claude Code, Gemini CLI, OpenCode, Cursor, Cline and the standard OpenAI,
  Anthropic and Gemini clients). Discovery and inference compatibility are separate claims, and
  Busbar claims neither for a client or version it has not tested.
- An admin API that speaks kinds rather than plugins: discover a kind, then its instances, then each
  instance's schema, state and data.

## After 1.6.0

Direction under consideration, in no committed order:

- Per-user OAuth for MCP tool servers, which needs a neutral per-user credential seam first.
- An opt-in, digest-pinned mirror of an upstream MCP server's resources and prompts.
- Provider additions that were deferred from 1.6.0: Fal video, and Replicate video, image and
  speech.
- A third-party operator authentication plugin. In 1.6.0 the operator plugin must be first-party
  and signed; `plugins.trust.operator` is reserved and refused until a customer needs it.
- Model-deprecation impact reporting. Busbar supplies factual identities and explicit coverage;
  lifecycle policy, dates, contacts and notices belong to the Console.

## Not planned

- Code mode inside the core.
- Semantic caching in the request hot path.
- Aliases, deprecated spellings and compatibility flags for 1.5.5 surfaces. 1.6.0 removes a
  surface rather than keeping it beside its replacement, and documents the removal in the
  migration guide.

## Reporting a gap

Security issues go through [SECURITY.md](../SECURITY.md). For other reports and requests, see
[CONTRIBUTING](../CONTRIBUTING.md).
