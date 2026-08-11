// THE DIAGNOSTIC UPSTREAM: a registered MCP tool server for busbar to sit in front of, so the
// official suite's CONTENT scenarios have something to reach.
//
// WHY THIS EXISTS AND WHY IT IS NOT THE SUITE'S OWN REFERENCE SERVER.
//
// Most of the suite's server scenarios call a named diagnostic tool — `test_simple_text`,
// `test_image_content`, and so on — and judge the content blocks that come back. Pointed at a
// busbar with an EMPTY registry every one of them fails with "is not a tool this server exposes",
// which says nothing about busbar's conformance: it is the correct answer for a gateway with
// nothing registered.
//
// The obvious move is to put the spec authors' own `everythingServer` behind busbar, and it does
// not work, for a reason that is a busbar DESIGN rather than an oversight. busbar's routing key is
// `{server}_{tool}`: a tool is namespaced by the server it was registered under, because two
// registered servers may legitimately expose the same tool name and keying the catalogue on the
// bare one lets the second silently answer for the first. The reference server already names its
// tools `test_simple_text`, so through busbar they would surface as `<server-id>_test_simple_text`
// and no scenario would find them. Registering it under the id `test` with tools named
// `simple_text` reproduces the exact names the suite asks for, through the real namespacing, with
// nothing bypassed — which is what this file serves.
//
// WHAT IS AND IS NOT PROVEN BY A GREEN HERE. This server is a CONTENT SOURCE, not a stand-in for
// busbar: every scenario still crosses busbar's whole path — admission under the caller's grant,
// the pin-generation re-check, the approved-digest gate, credential selection bound to the inbound
// principal, and output normalisation. What is being judged is busbar's proxying, and this fixture
// is only what there is to proxy.
//
// THE CONTENT IS THE SPEC'S, VERBATIM. Each tool returns the shape the scenario's own
// documentation prescribes. A fixture that returns something merely plausible would make a red
// here mean "the fixture guessed wrong", which is the class of unreadable verdict the whole
// conformance harness is arranged to avoid.

import { createServer } from "node:http";

const PORT = Number(process.argv[2]);
if (!PORT) {
  console.error("usage: diagnostic-upstream.mjs <port>");
  process.exit(2);
}

// A 1x1 PNG and a minimal WAV header. Deliberately tiny: the scenarios check that the block has a
// `data` field and the declared mime type, never that the bytes decode to anything in particular,
// and a real asset here would be a large file in the repository for no added coverage.
const PNG_1X1 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
const WAV_SILENCE =
  "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=";

// The tool table. The KEY is the bare name busbar registers and calls with; the suite sees
// `test_<key>` because busbar namespaces it under the server id `test`.
const TOOLS = {
  simple_text: {
    description: "Returns a simple text content block.",
    result: () => ({
      content: [
        { type: "text", text: "This is a simple text response for testing." },
      ],
    }),
  },
  image_content: {
    description: "Returns a single image content block.",
    result: () => ({
      content: [{ type: "image", data: PNG_1X1, mimeType: "image/png" }],
    }),
  },
  audio_content: {
    description: "Returns a single audio content block.",
    result: () => ({
      content: [{ type: "audio", data: WAV_SILENCE, mimeType: "audio/wav" }],
    }),
  },
  embedded_resource: {
    description: "Returns an embedded resource content block.",
    result: () => ({
      content: [
        {
          type: "resource",
          resource: {
            uri: "test://embedded-resource",
            mimeType: "text/plain",
            text: "This is an embedded resource content.",
          },
        },
      ],
    }),
  },
  multiple_content_types: {
    description: "Returns text, image and resource content blocks together.",
    result: () => ({
      content: [
        { type: "text", text: "Multiple content types test:" },
        { type: "image", data: PNG_1X1, mimeType: "image/png" },
        {
          type: "resource",
          resource: {
            uri: "test://mixed-content-resource",
            mimeType: "application/json",
            text: '{"test":"data","value":123}',
          },
        },
      ],
    }),
  },
  // `isError: true` is a TOOL-LEVEL error and is deliberately NOT a JSON-RPC error: the call
  // succeeded, the tool reported a failure, and the distinction is the whole point of the field.
  // busbar proxies the result through untouched, so what the suite judges is that busbar did not
  // convert a tool's own error report into a transport failure of its own.
  error_handling: {
    description: "Always reports a tool-level error.",
    result: () => ({
      isError: true,
      content: [
        {
          type: "text",
          text: "This tool intentionally returns an error for testing",
        },
      ],
    }),
  },
};

// ── THE SEP-2322 FIXTURE TOOLS ───────────────────────────────────────────────────────────────────
//
// These exist so the `input-required-result-*` scenarios have a tool to name. They are the ORDINARY
// KIND: each returns a plain complete result and knows nothing whatsoever about MRTR.
//
// That is the whole point, and it is worth being explicit because the opposite would be the easy
// mistake. The ask those scenarios observe is BUSBAR'S OWN — composed from the operator's
// `ask_caller:` configuration in boot.sh, filtered by the caller's declared capabilities, and sealed
// with a `requestState` busbar mints. It is emitted BEFORE busbar dispatches anywhere, so on the
// first request this upstream is never contacted at all. What it serves is the retry: the call that
// finally runs once the caller has answered.
//
// An upstream that returned an `InputRequiredResult` of its own would be testing the opposite
// property, and busbar's answer to that is a refusal — see `mcp/inputreq.rs`. That case is exercised
// by the in-tree battery's hostile peer, deliberately not here: this fixture is a content source,
// and a content source that also mounted an attack would make every red ambiguous.
// SEP-2575 (the `server-stateless` scenario). Three tools whose ABSENCE made four of that
// scenario's checks report "Not testable" rather than pass or fail — a shape worth naming, because
// an untestable check is counted as a FAILURE by the suite and reads in the summary exactly like a
// broken implementation.
//
// `missing_capability` is the interesting one: it asks the caller for a SAMPLING round trip, and the
// scenario calls it declaring NO capabilities. What is being judged is busbar's own refusal —
// `-32021 MissingRequiredClientCapability` rather than the generic `-32000` — so the ask is
// configured in `boot.sh`'s `ask_caller:` and this fixture only supplies the body for the round that
// runs once the caller HAS answered.
TOOLS.missing_capability = {
  description:
    "SEP-2575: requires the `sampling` client capability (drives the -32021 undeclared-capability rejection)",
  result: () => ({
    content: [{ type: "text", text: "sampling round-trip complete" }],
  }),
};

// A plain successful call. The check asserts only that the response stream carries no INDEPENDENT
// top-level JSON-RPC request — so the tool must NOT elicit, and the reference server's own does not
// either. Returning content is the whole fixture.
TOOLS.streaming_elicitation = {
  description:
    "SEP-2575: yields a response stream carrying no independent top-level JSON-RPC requests",
  result: () => ({
    content: [
      { type: "text", text: "stream observed: result frames only, no top-level requests" },
    ],
  }),
};

// The no-log-without-logLevel rule. The scenario omits `_meta` logging level and asserts that NO
// `notifications/message` frame appears. Busbar's log records ride the SSE response stream and are
// filtered by the level named in the request's own `_meta` — so what this fixture exercises is
// busbar's gating, not the upstream's.
TOOLS.logging_tool = {
  description:
    "SEP-2575: logs through the request-scoped, logLevel-gated channel so the no-log-without-logLevel rule is exercised",
  result: () => ({
    content: [
      { type: "text", text: "logged through the request-scoped, logLevel-gated channel" },
    ],
  }),
};

// A1.4 / `tools-call-with-progress`. The ONLY fixture here that answers with a STREAM rather than a
// single JSON document, because progress is defined by WHEN it arrives: `notifications/progress`
// frames precede the result on the same response, and a fixture that returned them alongside the
// result would be testing nothing.
//
// THE SPEC RULE THIS ENCODES, and it is a MUST NOT rather than a MAY: a server must not emit
// progress without a client-supplied `progressToken`. So the token is echoed back as the content
// when one is present and the string `no-progress-token` when it is not — which is what makes the
// negative case observable instead of merely absent.
TOOLS.tool_with_progress = {
  description: "Reports progress notifications while it runs.",
  // Marked rather than inferred: `send_stream` below keys off this, so a tool cannot start streaming
  // by accident.
  streams: true,
  result: (progressToken) => ({
    content: [{ type: "text", text: String(progressToken ?? "no-progress-token") }],
  }),
};

// `json-schema-2020-12` (SEP-1613 / SEP-2106). The schema is the fixture: the scenario reads the
// tool's `inputSchema` off `tools/list` and checks the 2020-12 keywords survive the hop. busbar
// publishes the OPERATOR's declared schema rather than the upstream's, so what this proves is that
// a full 2020-12 document travels through the `tools:` grammar without being flattened.
TOOLS.schema_2020_12_tool = {
  description:
    "Tool with JSON Schema 2020-12 features for conformance testing (SEP-1613, SEP-2106)",
  result: () => ({
    content: [{ type: "text", text: "JSON Schema 2020-12 tool called" }],
  }),
};

const MRTR_FIXTURES = {
  input_required_result_elicitation: "Runs once the caller has supplied its name.",
  input_required_result_sampling: "Runs once the caller has supplied a completion.",
  input_required_result_list_roots: "Runs once the caller has supplied its roots.",
  input_required_result_request_state: "Runs once the caller has echoed the request state.",
  input_required_result_multiple_inputs: "Runs once the caller has answered every requested input.",
  input_required_result_multi_round: "Runs once the caller has completed both input rounds.",
  input_required_result_tampered_state: "Runs once the caller has echoed unmodified request state.",
  input_required_result_capabilities: "Runs once the caller has supplied a completion.",
};

for (const [name, description] of Object.entries(MRTR_FIXTURES)) {
  TOOLS[name] = {
    description,
    // `state-ok` is in the text because the `request-state` scenario's DESCRIPTION asks for it. Its
    // checks do not read it (they only test `isCompleteResult`), so this is not what makes that
    // scenario pass — it is here so a human reading the transcript can see that the round busbar
    // gated actually ran.
    result: () => ({
      content: [{ type: "text", text: `state-ok: ${name} completed after the requested input.` }],
    }),
  };
}

// ── THE SEP-2663 (TASKS EXTENSION) FIXTURE TOOLS ─────────────────────────────────────────────────
//
// The tasks scenarios name their tools BARE — `slow_compute`, `failing_job`, `protocol_error_job`,
// `confirm_delete`, `multi_input` — and busbar's routing key is `{server}_{tool}`. Every one of
// those names contains the separator, so each is reachable by choosing the server id that composes
// it: `slow` + `compute`, `failing` + `job`, `protocol` + `error_job`, `confirm` + `delete`,
// `multi` + `input`. That is the same device the `test` and `json` registrations already use, and it
// goes through the REAL namespacing with nothing bypassed — see this file's header.
//
// `greet` is the ONE name in the suite that has no separator in it, so no server id produces it.
// It is reached by the OTHER mechanism, which is an owner decision and not a fixture's: the
// registration writes `tools_allow.greet.publish_as: greet`. The property the routing key protects —
// one wire name resolving to exactly one (server, tool) — is unchanged; what changed is that it is
// now kept by `mcp::config::validate_published_names`, which refuses boot on a duplicate, instead of
// by construction. See `greeter:` in boot.sh and TOOLS.greet below.
//
// WHAT THESE FIXTURES ARE AND ARE NOT. They are a CONTENT SOURCE, exactly as the content tools
// above are. The whole task lifecycle — creating the task, parking it on input, resuming it,
// settling it, the `-32021` gate, the wire shapes — is BUSBAR's, in `mcp/tasks.rs`, and is what the
// scenarios judge. What lives here is only the work a task wraps: something slow enough to still be
// running when the poll arrives, something that reports a tool-level error, and something that
// fails at the protocol level.

// The slow one. `seconds` is honoured for real, because every timing assertion in the suite depends
// on it: `seconds: 0` must be observable as an immediate result, `seconds: 2` must still be
// `working` when the first `tasks/get` lands, and `seconds: 60` must not settle before a
// `tasks/cancel` can reach it. A fixture that returned instantly would make the cancel checks pass
// for the wrong reason — there would be nothing left to cancel.
TOOLS.compute = {
  description: "SEP-2663: sleeps for `seconds` and then returns a result.",
  sleepSeconds: (args) => Number(args?.seconds ?? 0),
  result: (_progressToken, args) => ({
    content: [
      {
        type: "text",
        text: `slow_compute finished: label=${args?.label ?? "none"} seconds=${args?.seconds ?? 0}`,
      },
    ],
  }),
};

// A TOOL-LEVEL error, and the distinction it encodes is the one SEP-2663 is most often implemented
// backwards. This tool RAN. It did its work and the work failed, so the call succeeded and
// `isError` says what happened — which busbar must surface as `completed` + `result.isError`, NOT
// as `failed`. `failed` is for a protocol error, and `error_job` below is what one of those looks
// like.
TOOLS.job = {
  description: "SEP-2663: always reports a tool-execution error after a short delay.",
  sleepSeconds: () => 1,
  result: () => ({
    isError: true,
    content: [{ type: "text", text: "failing_job: the job ran and failed" }],
  }),
};

// A PROTOCOL error: a JSON-RPC error response rather than a result carrying `isError`. Nothing ran,
// so there is no tool output to report, and busbar must settle the task as `failed` with an inlined
// `error{code,message}` and no `result` at all.
TOOLS.error_job = {
  description: "SEP-2663: fails at the protocol level (JSON-RPC error, no result).",
  rpcError: { code: -32000, message: "protocol_error_job: the handler failed" },
};

// The two MRTR-inside-a-task tools. Neither knows anything about input: the asks are BUSBAR's own,
// composed from `task_ask_caller:` in boot.sh, parked on the task and answered with `tasks/update`.
// What these serve is the round that finally runs once the caller has answered — the same division
// of labour the SEP-2322 fixtures above already use, moved from the synchronous loop onto a task.
TOOLS.delete = {
  description: "SEP-2663: deletes the named file once the caller has confirmed.",
  result: (_progressToken, args) => ({
    content: [
      {
        type: "text",
        text: `confirm_delete completed for ${args?.filename ?? "(no filename)"}`,
      },
    ],
  }),
};

TOOLS.input = {
  description: "SEP-2663: runs once the caller has answered both parallel input requests.",
  result: () => ({
    content: [{ type: "text", text: "multi_input completed after both inputs" }],
  }),
};

// THE COMPOSITION TOOL (`test_tool_with_task`). Round 1 is busbar's synchronous MRTR ask; round 2
// escalates to a task. The scenario asserts END TO END that the answer gathered in round 1 reaches
// the task's eventual result — an implementation that wires MRTR and tasks as two independent
// surfaces produces a task result with no trace of the answer and fails here.
//
// Which is why this ECHOES rather than returning a fixed string: busbar binds an `ask_caller:` entry
// keyed `user_name` to the tool argument of the same name, so the elicitation response arrives in
// `arguments.user_name` and the text below is the only place a human — or the scenario — can see
// that the round trip actually happened.
TOOLS.tool_with_task = {
  description: "SEP-2663: gathers a name, then escalates to a task that greets it.",
  result: (_progressToken, args) => {
    const answer = args?.user_name;
    const name = answer?.content?.name ?? answer?.name ?? "(no name gathered)";
    return {
      content: [{ type: "text", text: `Hello, ${name}! (gathered during the MRTR phase)` }],
    };
  },
};

// `greet` — THE SYNCHRONOUS BASELINE the tasks scenarios measure everything else against.
//
// Four checks call it and all four require the SAME thing: a plain `ToolResult` with a non-empty
// `content[]`, no `resultType: "task"` and no top-level `taskId`. So it declares no `task_support`
// in boot.sh and does no work here — a tool that could ever answer with a task would make
// `TasksSyncToolCall` pass or fail depending on which branch ran, which is the opposite of a
// baseline.
//
// It is reachable because the registration in boot.sh writes `publish_as: greet`. See the comment
// there: `greet` carries no separator, so no server id composes it, and it is the one name in the
// suite the `{server}_{tool}` default cannot express.
TOOLS.greet = {
  description: "Returns a greeting for the supplied name, synchronously and always.",
  result: (_progressToken, args) => ({
    content: [{ type: "text", text: `Hello, ${args?.name ?? "world"}!` }],
  }),
};

// SEP-2243 §"Server Behavior for Custom Headers". The tool exists so busbar has an `x-mcp-header`
// annotation to VALIDATE — the annotation itself is declared in the operator's `input_schema` in
// boot.sh, because busbar publishes the operator's schema and never the upstream's, so this side of
// the fixture only has to be callable and echo what it was given.
TOOLS.header_param = {
  description: "SEP-2243: echoes a parameter that is mirrored into an Mcp-Param header.",
  result: (_progressToken, args) => ({
    content: [{ type: "text", text: `tenant=${args?.tenant ?? "(none)"}` }],
  }),
};

const TOOL_LIST = Object.entries(TOOLS).map(([name, t]) => ({
  name,
  description: t.description,
  inputSchema: { type: "object", properties: {} },
}));

const send = (res, status, payload) => {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
};

/// Answer as `text/event-stream`: the progress notifications first, then the result, each its own
/// `data:` frame. This is the shape revision `2026-07-28` leaves for SSE — a RESPONSE content type
/// on the POST, not a standing GET stream — so one request still yields one response, and the only
/// thing that changes is that it arrives as a sequence.
const sendStream = (res, id, tool, progressToken) => {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-store",
  });
  // MUST NOT emit progress without a caller-supplied token. Silence here is the conformant answer,
  // not a degraded one.
  if (progressToken !== undefined) {
    for (const progress of [0, 50, 100]) {
      const frame = {
        jsonrpc: "2.0",
        method: "notifications/progress",
        params: {
          progressToken,
          progress,
          total: 100,
          message: `Completed step ${progress} of 100`,
        },
      };
      res.write(`data: ${JSON.stringify(frame)}\n\n`);
    }
  }
  const result = {
    jsonrpc: "2.0",
    id,
    result: { resultType: "complete", ...tool.result(progressToken) },
  };
  res.write(`data: ${JSON.stringify(result)}\n\n`);
  res.end();
};

const rpcError = (res, status, id, code, message) =>
  send(res, status, { jsonrpc: "2.0", id, error: { code, message } });

createServer((req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405, { allow: "POST" });
    res.end();
    return;
  }
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return rpcError(res, 400, null, -32700, "not valid JSON");
    }
    const id = msg?.id ?? null;
    // The mirrored headers this revision requires. Checked rather than ignored, because busbar
    // builds them and an upstream that never looks would let a regression in busbar's OUTBOUND
    // envelope go unnoticed — the direction this fixture is uniquely placed to observe.
    if (req.headers["mcp-method"] !== msg?.method) {
      return rpcError(res, 400, id, -32020, "Mcp-Method does not mirror the body");
    }
    const meta = msg?.params?._meta;
    if (!meta?.["io.modelcontextprotocol/protocolVersion"]) {
      return rpcError(res, 400, id, -32602, "params._meta must carry the protocol version");
    }
    if (msg.method === "tools/list") {
      return send(res, 200, {
        jsonrpc: "2.0",
        id,
        result: {
          resultType: "complete",
          ttlMs: 0,
          cacheScope: "private",
          tools: TOOL_LIST,
        },
      });
    }
    if (msg.method === "tools/call") {
      const tool = TOOLS[msg?.params?.name];
      if (!tool) {
        return rpcError(res, 200, id, -32602, `unknown tool ${msg?.params?.name}`);
      }
      if (tool.streams) {
        return sendStream(res, id, tool, meta?.progressToken);
      }
      const args = msg?.params?.arguments ?? {};
      // A PROTOCOL error, distinct from a result carrying `isError` — see `error_job` above for
      // why the two are different answers and not two spellings of one.
      if (tool.rpcError) {
        return rpcError(res, 200, id, tool.rpcError.code, tool.rpcError.message);
      }
      const answer = () =>
        send(res, 200, {
          jsonrpc: "2.0",
          id,
          result: { resultType: "complete", ...tool.result(undefined, args) },
        });
      // A REAL delay when the tool declares one. The SEP-2663 scenarios assert on WHEN a task
      // settles — still working at the first poll, still cancellable sixty seconds later — so a
      // fixture that returned instantly would make every cancel check pass with nothing to cancel.
      const seconds = tool.sleepSeconds ? tool.sleepSeconds(args) : 0;
      if (seconds > 0) {
        const timer = setTimeout(answer, seconds * 1000);
        // busbar ABORTS the in-flight upstream request when a task is cancelled, which drops the
        // connection. Clearing the timer on close stops this process holding a pending write to a
        // socket nobody is reading for the rest of the run.
        res.on("close", () => clearTimeout(timer));
        return undefined;
      }
      return answer();
    }
    return rpcError(res, 404, id, -32601, `method ${msg.method} is not implemented`);
  });
}).listen(PORT, "127.0.0.1", () => {
  console.log(`diagnostic upstream listening on 127.0.0.1:${PORT}`);
});
