# What's new in Busbar 1.6.0, and upgrading from 1.5.5

**Busbar 1.6.0 keeps your 1.5.5 deployment and makes it much harder to attack.** Every 1.5.5
config key still means what it meant. Every key you minted still verifies, and every durable store
opens on the data it already holds. One command converts your config file, and `busbar --validate`
tells you before you restart whether anything else needs a step. The short list of those steps is
at the end of this page, each one named and explained, so nothing is a surprise.

What you get for the upgrade: a gateway that refuses to be turned against your own network, never
repeats a credential back to you, tells you when something you configured does nothing, and keeps a
signed, tamper-evident record you can verify without our software. On top of that sit four new
planes (MCP tools, A2A agents, realtime voice and decisions), each switched off until you write its
section.

How we know it carries over: the same configs, the same requests and the same plugins were run
through the published 1.5.5 binary and through 1.6.0, and every difference was reviewed and signed
off one by one. The ones you might notice are all on this page.

---

## Your upgrade, in one command

```sh
busbar --migrate-config config.yaml > config-1.6.yaml   # convert the config
busbar --validate -c config-1.6.yaml                    # check it, with no network and no side effects
```

Then install the 1.6.0 binary, point it at the new file and start it.

What `--migrate-config` does for you:

- **Adds the `store:` block.** 1.6.0 asks the config to say which store it runs on. A 1.5.5 config
  without one ran on the in-memory store, so the migration writes exactly that,
  `store: {module: memory}`. Nothing about how it runs changes. A config that already names a store
  is left as written.
- **Rewrites the old hook spellings.** `plugin:` becomes `module:` and a single-stage `at:` becomes
  `phase:`. The old spellings still work in 1.6.0; the rewrite just puts your file in the documented
  form. A saved config overlay is rewritten the same way when Busbar starts.
- **Pins the 1.6.0 plugins.** Each plugin your config uses that this binary does not carry gets a
  `plugins.fetch` pin to its 1.6.0 release, found in the release index; a pin to a 1.5.5-era
  release is rewritten. A 1.5.5 build left beside its 1.6.0 build only warns at startup.
- **Lets each plugin migrate its own settings.** Core never edits inside a plugin's section: each
  plugin's own migration does, and its report lines are printed under its name. Your webhook
  exporter's auth header that 1.5.5 never sent is removed that way, and the private provider and
  sign-in hosts you used are reported and added to `advanced.allow_destinations`, exactly those
  hosts.
- **Keeps your bill.** A `rate_card:` entry gains `units:` at `0` for every unit 1.5.5 never billed.
- **Keeps your users signed in.** A sign-in provider whose users 1.5.5 let through with no grant
  gets an explicit `role_bindings.<provider>."*": {}`, with a warning to tighten it.
- **Drops block-list entries that never matched.** An entry naming no usable host is removed.
- **Leaves everything else exactly as you wrote it.** Pools, members, weights, providers and models
  are not touched. When there is nothing to decide, the output has no banner and no comments: it
  reads like a file you wrote by hand.
- **Never guesses.** Where a decision belongs to you, the migration prints a `TODO(migrate)` line
  naming the key instead of choosing for you.

What carries over without the migration doing anything:

- **Your keys.** `auth.signing_key` is read as before, so every outstanding key keeps verifying.
  Nothing is re-minted.
- **Your data.** A SQLite, Postgres, MySQL or Valkey store opens on its 1.5.5 contents: keys,
  groups, audit records and usage history. Usage history is converted to the 1.6.0 layout on first
  read by a migration that is safe to interrupt and rerun.
- **Your plugin names.** A config that names a first-party plugin by its 1.5.5 name (for example
  `module: busbar-webrequest`) still resolves to the 1.6.0 plugin.
- **Your environment variables.** The deprecated `BUSBAR_*` variables are honoured exactly as in
  1.5.5, with the same warning naming the config key that replaces them.
- **Your CI.** `--validate` reads the same references startup reads, with no network and no side
  effects, so running the 1.6.0 binary's `--validate` in CI tells you before you deploy whether it
  will start. The cases it cannot see are marked in the list at the end of this page.
- **Your log pipeline.** Plugins write their own log files, and every plugin warning and error is
  also a line of busbar's own log, tagged with the plugin's name.

The full step-by-step guide is [Migrating from 1.5.x to 1.6.0](migration-1.6.md).

---

## Security hardening

Each item says what 1.5.5 did and what 1.6.0 does instead.

### Your network stays yours

- **Private addresses are off limits by default.** Before: a provider or identity provider URL could
  point anywhere, including your internal network. After: a dial to a private or loopback address
  is refused unless you name it in `advanced.allow_destinations`.
- **One guard for every outbound connection.** Before: separate checks covered provider URLs and
  telemetry webhooks. After: one guard judges every connection Busbar opens, including MCP tool
  servers, A2A agents, streaming and WebSocket upstreams and plugin downloads. Cloud metadata
  services and IPv6 link-local addresses are refused everywhere unless you allow that exact address.
- **DNS rebinding is closed.** Before: a URL's host was checked as written. After: Busbar resolves
  the name, judges every address it returned (one bad address refuses the whole answer), and
  connects to exactly the address it judged, so a name that changes its answer cannot slip through.
- **Your block list means what it says.** Before: a block-list entry written in Unicode (full-width
  digits, for example) matched nothing, and the address it named was dialled. After: entries are
  read exactly the way the destination is read, so they block what they name. An entry that could
  never match anything is no longer silently ignored.
- **Identity providers cannot bounce Busbar inward.** Before: the OIDC plugin followed up to ten
  redirects on discovery and key fetches with no address check. After: a redirect from a public host
  into a private network, or to a metadata service from anywhere, is refused, and each hop is judged
  by the host that sent it.
- **Tenants never see your account's state.** New in 1.6.0, callers receive the provider's own
  response headers. Busbar strips the cookies the provider sets for its own connection and your
  account-wide rate-limit headers, so one tenant never learns another's usage.

### Credentials are handled like credentials

- **A secret is never echoed.** Before: a literal credential pasted where a secret reference belongs,
  or an unreadable service-account key file, could appear in the error message. After: Busbar refuses
  it and the message names the setting, never the value.
- **A provider credential that cannot be found stops startup.** Before: Busbar logged one warning and
  started the provider with an empty key, which looked healthy and failed every request. After:
  startup stops and names the provider and the reference. A provider that genuinely takes no key
  says so with `api_key: none`.
- **Secret files are read safely.** Before: a secret path that was a directory, device or pipe could
  hang startup or fail with a bare system error. After: it is refused by name, and an unset variable
  and a badly encoded one are reported as different problems.
- **Self-service key rotation needs your page.** Before: any website could trigger a signed-in user's
  key rotation through a link. After: rotation happens only from Busbar's own key page.

### Plugins you can trust

- **No downgrade attacks.** Before: anyone who could write to the plugins directory could swap in an
  old, genuinely signed release with a known defect, and it loaded without a warning. After: Busbar
  remembers the highest version of each plugin it has loaded and refuses an older one unless you roll
  back on purpose, which is itself recorded.
- **One checked interface for every plugin.** Before: a plugin exchanged JSON with the host, and a
  compiled-in plugin could reach Busbar's own metrics. After: every plugin, compiled in or dropped
  in, goes through the same interface, and every answer it gives is size-checked and validated before
  Busbar uses it.
- **Plugins cannot impersonate Busbar.** A plugin can report metrics and diagnostics, but Busbar
  validates and bounds them, and a plugin cannot write a Busbar metric or invent a Busbar diagnostic
  code.

### Nothing silent

- **Error and warning lines carry a code.** Each `BUSBAR-NNNN` code can be looked up in [the diagnostics reference](diagnostics.md): what it means, and exactly
  what to do.
- **Untranslatable content is named, not faked.** Before: when a request crossed between provider
  formats, content the target could not carry was replaced with empty text or a guessed value.
  After: it is dropped with a warning and an audit record naming exactly what was dropped.
- **A stream that dies is not billed as a success.** Before: a stream that failed partway could be
  recorded as complete. After: it is recorded as failed and the provider is marked accordingly.
- **Hooks fail closed when you said they should.** Before: a hook set to `on_error: reject` whose
  transform failed let the request through. After: the request is refused, as the setting promised.

### Evidence you can check yourself

- **A tamper-evident record, now covering tools and agents.** Governance and admin changes, MCP
  tool calls and agent task history are written to a hash-chained record signed with Ed25519. Busbar
  re-verifies the chain at startup and on demand.
- **Verifiable without Busbar.** New admin reads serve the chain's head, its public keys and any
  range of records, and the record format is published
  ([audit chain format](https://github.com/GetBusbar/busbar/blob/main/docs/audit-chain-digest-v4.md)),
  so a third party can check a node's audit chain with their own code. Each record names the format
  it was sealed under.
- **Bills you can re-derive.** Rate cards are now a dated history. Each request is priced at the card
  in force when it arrived, a card edit never reprices the past, and a correction is a recorded,
  attributed entry rather than an edit.

---

## What's new

### Four new planes, all optional

A config with none of these sections gains no endpoint and no route. Write the section to turn one
on.

- **MCP.** Busbar is an MCP server and a governed gateway in front of your MCP tool servers, over HTTP
  and over stdio, with tool approval and change detection
  ([MCP guide](https://github.com/GetBusbar/busbar/blob/main/docs/mcp.md),
  [tool and agent trust](tool-and-agent-trust.md)).
- **A2A.** Busbar serves the A2A protocol over JSON-RPC, HTTP+JSON and gRPC in front of your
  registered agents ([A2A guide](https://github.com/GetBusbar/busbar/blob/main/docs/a2a.md)).
- **Realtime voice.** A `streams:` section serves full-duplex realtime sessions over the OpenAI
  Realtime and Gemini Live formats ([voice guide](voice.md)).
- **Decisions.** A `decisions:` section serves decision engines as a byte-for-byte passthrough.

Everything a model request already gets applies to all of them unchanged: the caller's key, its
grants, its budget, hooks, failover pools, circuit breaking, metrics and the audit record.

### One plugin system

- **Seven kinds, one way to build them:** store, secret, auth, hook, export, plane and transport. A
  plugin compiled into Busbar and the same plugin dropped in as a signed file behave identically.
- **Signed, versioned and checked before load.** `busbar --list-plugins` reads the signed manifests
  without running any plugin code, and `busbar --validate` checks signature, trust, version floor and
  compatibility with no side effects ([plugins](plugins.md)).
- **Each plugin gets its own log file**, under `plugins.logs.dir`, with its own level and rotation.
- **Plugin authors** rebuild against the 1.6.0 SDK with
  [the SDK migration guide](plugin-sdk-migration-1.6.md).

### Provider options by their own names

Set any request option your provider accepts, under `providers.<name>`, using the provider's own
name for it, for example `OpenAI-Organization` or `OpenAI-Project`. Busbar checks every key at
startup and refuses an unknown one, listing the names that provider accepts. Credentials stay where
they were, in `api_key`.

### More faithful to every provider

Every request and response Busbar produces is checked against the providers' published API
specifications for OpenAI (Chat Completions and Responses), Anthropic, Google Gemini, AWS Bedrock and
Cohere. Responses carry the fields those specifications require, streams carry the events they
declare, and citations, documents, audio and video now cross between formats instead of being
flattened.

---

## Things you might notice

This is the complete list of what a 1.5.5 deployment can see change. Each item says what the
migration does about it.

### Might need one step before you restart

`busbar --validate` names every item in this group that applies to you, except where noted.

| What changed | What to do | Done for you? |
|---|---|---|
| A config must have a `store:` block. | Nothing. | Yes, `--migrate-config` adds it. |
| Hook `plugin:` and `at:` keys are the old spellings. | Nothing; they still work. | Yes, `--migrate-config` rewrites them. |
| A plugin named by its 1.5.5 name. | Nothing. | Yes, the old name still resolves. |
| 1.5.5 builds of the SQLite, Postgres, MySQL and Valkey stores, the OIDC, GitHub and LDAP sign-in plugins, the Vault secret plugin and the web-request hook do not load in 1.6.0. | Nothing, on a host with network. Your data carries over: the new store plugin opens the same database. On a host with no network, copy the 1.6.0 tarballs into `plugins.dir`. | Yes, `--migrate-config` pins each 1.6.0 release in `plugins.fetch` and rewrites old pins; an old build beside its 1.6.0 build only warns. |
| A plugin built by someone else for 1.5.5 does not load. | Its author rebuilds it with [the SDK migration guide](plugin-sdk-migration-1.6.md). | No. |
| A `rate_card:` must price every billable unit a provider reports, not only tokens. | Nothing, to keep 1.5.5's bill exactly; set real rates when you want to bill those units ([how](migration-1.6.md#a-card-must-configure-every-billable-unit-its-plane-counts)). | Yes, `--migrate-config` adds every unit at `0`. |
| A provider or identity provider on a private or loopback address (a local ollama or vLLM, an in-cluster gateway, an internal DNS name) is refused by default. `--validate` names a provider URL the guard will refuse; it cannot see an identity provider's. | Nothing. | Yes, `--migrate-config` adds exactly the hosts the provider's plane and the sign-in plugins report to `advanced.allow_destinations`. |
| A provider `api_key` reference that does not resolve stops startup instead of running the provider with an empty key. | Fix the reference, or write `api_key: none` for a provider that takes no key. The migration does not guess this for you, because guessing wrong would disarm a provider that needs a key. | No, by design; `--migrate-config` names each one in a TODO. |
| A metadata block-list entry that names no usable host (for example `db.1`) is no longer silently ignored. | Nothing. | Yes, `--migrate-config` removes it; it never matched anything. |
| A webhook exporter's auth header that cannot be built as an HTTP header is refused at validation. 1.5.5 silently sent the webhook without it. | Nothing. | Yes, the exporter's own migration removes it and says 1.5.5 never sent it. |
| A `file:` secret that is a directory, device or pipe is refused. | Point it at a regular file. | No. |
| A signed-in user that your role bindings grant nothing is refused (401). 1.5.5 let such users through with no pool limits and no budget. | Review the binding the migration wrote and tighten it. | Yes, `--migrate-config` writes `role_bindings.<provider>."*": {}` (every pool, no budget) with a warning. |
| An identity provider reached by a DNS name whose discovery or key URL redirects to a private address fails sign-in. `--validate` does not catch this. | Point the issuer at the address it finally serves from. | No. |
| Plugin log lines, including the model plane's warnings, go to each plugin's own file under `plugins.logs.dir` (default `logs/plugins/`). | Nothing: every plugin warning and error is also a line of busbar's own log, tagged with the plugin. Add the directory to your log collection for the rest. | Yes. |

### Behaviour you might see, with nothing to change

- **Log lines carry a code.** Error and warning lines start with `BUSBAR-NNNN:`; the text after it is
  unchanged. A log rule that matches the start of a line needs to allow for it.
- **`--help` is longer and `--version` prints a second line** with build provenance.
- **Plugin names and versions read differently** in startup messages and listings: first-party
  plugins are named `busbar-<kind>-<name>` and versioned 1.6.x.
- **Bills are complete.** Usage that 1.5.5 recorded as zero is now billed: streams served through a
  fallback, Gemini server-side tool tokens, streams cut or cancelled after the first byte (billed for
  what streamed), transcriptions answered in the OpenAI format, and units a provider reports beside
  its tokens (priced by your rate card). Keys with that traffic will show their real spend.
- **Rate cards are a dated history.** Editing a card prices what happens after the edit and never
  reprices the past; `GET /admin/usage` names the card version it used. To correct a past window,
  post a correction to `POST /api/v1/admin/ledger/amend-rate-history`. A rate card written through
  the admin API needs the same `units:` map as one in the config file.
- **Some refusals use a more accurate code.** An Anthropic-format quota refusal says `billing_error`
  (was `insufficient_quota`). Rotating a key with an overlong id answers 400 like its sibling
  endpoints (was 404). A sign-in plugin at capacity answers 503 with `Retry-After` (was 401). An
  identity provider that cannot answer at sign-in gives 503, retryable (was 401). A streamed chat
  request whose `stream_options` is not an object, or a field of the wrong type, gets a 400 in the
  caller's own format.
- **A failed fallback is reported in Busbar's own error format** and marks that provider as down,
  the same as a failed first attempt already did.
- **`busbar_lane_state` reads 2 while a provider is tripped** in a pool (1.5.5 could read 1). Alerts
  keyed on 1 for a tripped provider should key on 2.
- **Same-format requests carry the caller's own headers** to the provider (its user agent, beta and
  version headers), except the credential and tenant headers Busbar controls. Callers receive the
  provider's response headers, minus your account's cookies and rate-limit state.
- **A `stream: true` request is always answered as a stream**, even when the provider answered with
  one JSON body.
- **Self-service key rotation links work only from Busbar's own key page.** Anywhere else, the link
  shows the current key.
- **Audit entries gain a `scheme` field**, and new records are sealed under the published v4 format.
  Existing records keep verifying as they are. If you verify the chain with your own tool, add the
  v4 field order.
- **Hook admin views gain `fires_at`, `groups` and `phase`.** `at` is still served; it reads `null`
  once the hook's `at:` key has been migrated, so read `fires_at` for a hook's stages.
- **Data stores report real errors.** A Postgres store that cannot open names the server's error
  code and message instead of `db error`.
- **The LDAP plugin fails closed** on a malformed reply or a URL with no host, where 1.5.5 crashed.

The 1.6.0 [changelog](https://github.com/GetBusbar/busbar/blob/main/CHANGELOG.md) has the full detail
for every item on this page.
