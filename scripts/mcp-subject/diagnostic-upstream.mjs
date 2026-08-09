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
