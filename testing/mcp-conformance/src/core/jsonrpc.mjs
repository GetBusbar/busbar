// Deliberately low-level JSON-RPC helpers.
//
// The battery must be able to put BYTES on the wire that no well-behaved SDK
// would ever produce: truncated frames, duplicate ids, notifications carrying
// ids, responses to requests nobody made. So we never use an SDK to build our
// own messages. We build strings.

import { REVISION } from './spec.mjs';

export const PROTOCOL_VERSION_KEY = 'io.modelcontextprotocol/protocolVersion';
export const CLIENT_INFO_KEY = 'io.modelcontextprotocol/clientInfo';
export const CLIENT_CAPS_KEY = 'io.modelcontextprotocol/clientCapabilities';
export const SERVER_INFO_KEY = 'io.modelcontextprotocol/serverInfo';
export const SUBSCRIPTION_ID_KEY = 'io.modelcontextprotocol/subscriptionId';
export const PROGRESS_TOKEN_KEY = 'progressToken';

export const ERR = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  HEADER_MISMATCH: -32020,
  MISSING_REQUIRED_CLIENT_CAPABILITY: -32021,
  UNSUPPORTED_PROTOCOL_VERSION: -32022,
  // Retired codes. A 2026-07-28 implementation MUST NOT emit these.
  RETIRED_RESOURCE_NOT_FOUND: -32002,
  RETIRED_URL_ELICITATION_REQUIRED: -32042,
};

export const RETIRED_ERROR_CODES = [
  ERR.RETIRED_RESOURCE_NOT_FOUND,
  ERR.RETIRED_URL_ELICITATION_REQUIRED,
];

// The sub-range the spec reserves for itself.
export const SPEC_RESERVED_RANGE = [-32099, -32020];
export const SPEC_DEFINED_CODES = [
  ERR.HEADER_MISMATCH,
  ERR.MISSING_REQUIRED_CLIENT_CAPABILITY,
  ERR.UNSUPPORTED_PROTOCOL_VERSION,
];

/** Build the `_meta` block every modern request must carry. */
export function meta(opts = {}) {
  const m = {};
  if (opts.protocolVersion !== null) {
    m[PROTOCOL_VERSION_KEY] = opts.protocolVersion ?? REVISION;
  }
  if (opts.clientInfo !== null) {
    m[CLIENT_INFO_KEY] = opts.clientInfo ?? {
      name: 'mcp-independent-battery',
      version: '1.0.0',
    };
  }
  if (opts.capabilities !== null) {
    m[CLIENT_CAPS_KEY] = opts.capabilities ?? {};
  }
  if (opts.progressToken !== undefined) m[PROGRESS_TOKEN_KEY] = opts.progressToken;
  if (opts.extraMeta) Object.assign(m, opts.extraMeta);
  return m;
}

/** A well-formed modern request object. */
export function request(id, method, params = {}, metaOpts = {}) {
  return {
    jsonrpc: '2.0',
    id,
    method,
    params: { ...params, _meta: meta(metaOpts) },
  };
}

/** A well-formed notification object (no id, by definition). */
export function notification(method, params = {}, metaOpts = {}) {
  return {
    jsonrpc: '2.0',
    method,
    params: { ...params, _meta: meta(metaOpts) },
  };
}

/** Serialize to a single stdio frame. Never adds a trailing newline itself. */
export function frame(obj) {
  return typeof obj === 'string' ? obj : JSON.stringify(obj);
}

export function isResponse(msg) {
  return msg && typeof msg === 'object' && 'id' in msg
    && ('result' in msg || 'error' in msg);
}

export function isNotification(msg) {
  return msg && typeof msg === 'object' && !('id' in msg) && 'method' in msg;
}

export function isRequest(msg) {
  return msg && typeof msg === 'object' && 'id' in msg && 'method' in msg;
}

/** Structural check used by several assertions. */
export function classify(msg) {
  if (isRequest(msg)) return 'request';
  if (isResponse(msg)) return 'response';
  if (isNotification(msg)) return 'notification';
  return 'unknown';
}
