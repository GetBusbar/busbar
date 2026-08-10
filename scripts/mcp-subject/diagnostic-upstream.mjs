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
      return send(res, 200, {
        jsonrpc: "2.0",
        id,
        result: { resultType: "complete", ...tool.result() },
      });
    }
    return rpcError(res, 404, id, -32601, `method ${msg.method} is not implemented`);
  });
}).listen(PORT, "127.0.0.1", () => {
  console.log(`diagnostic upstream listening on 127.0.0.1:${PORT}`);
});
