// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane kind: the `Plane` trait and the `plane` module (IF §8, §10.4), one `kind!` block (W1-A4b).

crate::kind! {
    /// A plane maps one protocol (LLM dialects, MCP, A2A, streaming, decisions). It reports facts, usage, wants
    /// and intents. It never routes, retries, prices, authenticates, holds credentials or keys, delivers pushes,
    /// owns sockets or keeps state across replicas: core does. Per-request protocol state lives in `Session`
    /// (owned by the shim slots, §6.5); cross-request state lives in core records via LOOKUP/STORE/DELETE.
    /// Every intent names a protocol, a grant, a configured upstream name or a key, never a plugin (236).
    pub trait Plane: kind = 6, abi = 1, session {
        views {
        /// One client request. route = the D_ROUTE id core matched. auth = the one AUTH_* class core applied
        /// to **this request** (from the route's mask and operator config; round 15: on a route whose
        /// effective set holds both AUTH_PRINCIPAL and AUTH_TICKET core classifies per request, §12.11, so
        /// two requests on one route may carry different values). identity = generic ID_* records (the auth
        /// answer's identity prefix, or the claims of a core-verified ticket), empty for AUTH_PUBLIC and for
        /// AUTH_OPTIONAL without credentials. Round 15: ticket_record = the bytes the plane stored with the
        /// core ticket that admitted this request (MT_RECORD at MINT), non-empty only when auth ==
        /// AUTH_TICKET and the ticket carried one; a MINT_ONCE ticket is consumed at admission, so its record
        /// reaches exactly one request (today's `ticket.take`, handed back once).
        /// Round 10: carrier = the core-minted id of the line-carrier session this request is one line of
        /// (§12.23): non-zero exactly on a ROUTE_LINE route, the same value for every line of one carrier,
        /// never reused in the process; 0 elsewhere. work = the durable-work reference core is recovering
        /// (§12.24): non-empty exactly when flags has RQ_RECOVERY (the text a WORK_OPEN answered).
        pub struct PlaneReq<'a> {
            pub route: u32,
            pub flags: u32,
            pub auth: u32,
            pub _r: u32,
            pub method: crate::types::Str<'a>,
            pub path: crate::types::Str<'a>,
            pub query: crate::types::Str<'a>,
            pub headers: crate::types::Slice<'a, crate::types::Pair<'a>>,
            pub identity: crate::types::Bytes<'a>,
            pub request_id: u64,
            pub carrier: u64,
            pub work: crate::types::Str<'a>,
            pub ticket_record: crate::types::Bytes<'a>,
        }
        /// One upstream attempt (or probe target) core chose. dialect and model come from core config; params
        /// are that route's configured parameters; upstream = the configured upstream (member) name, operator
        /// vocabulary (an MCP server, an A2A agent, an LLM provider entry), never a plugin. flags = TGT_*.
        /// URL, TLS pin and client identity of that upstream are core config and never reach the plane.
        /// Round 13: provider = the plane-owned keys of that upstream's `providers:` entry, exactly as core
        /// validated them against this plane's D_PROVIDER_SCHEMA at config load: one UTF-8 JSON object
        /// (canonical, the same bytes on every attempt to that member; `{}` when the entry has none).
        /// Round 14: only the keys **this plane's** schema names (its projection of the resolved entry, never
        /// `protocol`, never a key only another plane declares; §8.6 provider keys). Nested
        /// lists and tables (error_map, model_capabilities) travel inside it; the plane parses it with its own
        /// JSON parser (AGREED 223) and may cache the parse per `upstream`.
        pub struct Target<'a> {
            pub attempt: u32,
            pub flags: u32,
            pub dialect: crate::types::Str<'a>,
            pub model: crate::types::Str<'a>,
            pub base_path: crate::types::Str<'a>,
            pub upstream: crate::types::Str<'a>,
            pub provider: crate::types::Str<'a>,
            pub params: crate::types::Slice<'a, crate::types::Pair<'a>>,
        }
        }
        pods {
        pub struct Respond {
            pub status: u32,
            pub flags: u32,
        }
        pub struct Forward {
            pub flags: u32,
            pub _r: u32,
        }
        /// Tail = path pattern text (`/v1/chat/completions`, `/mcp`, `{*rest}` wildcard). auth = mask of the
        /// AUTH_* classes this route may run under; core picks the effective set per operator config (default:
        /// the lowest bit, **plus AUTH_TICKET when the mask holds both AUTH_PRINCIPAL and AUTH_TICKET**: such a
        /// route accepts a core ticket in place of a principal and core classifies each request, §12.11).
        pub struct RouteRec {
            pub route: u32,
            pub methods: u32,
            pub flags: u32,
            pub auth: u32,
        }
        /// Round 23, D_ROUTE_CRED_HEADER: the D_ROUTE id it applies to. Tail = the header name.
        pub struct RouteHeaderRec {
            pub route: u32,
            pub _r: u32,
        }
        /// Carrier and credential intent for an upstream exchange (CARRIER_*, OUTBOUND_DEFAULT | OUTBOUND_NONE;
        /// round 22: the plane never states the credential mode, core derives it, §12.18). Optional first
        /// record of the `upstream` answer (exchange 0); absent = CARRIER_DEFAULT, OUTBOUND_DEFAULT.
        pub struct UpCarrier {
            pub carrier: u32,
            pub outbound: u32,
        }
        /// Starts upstream exchange `exchange` (≥ 1, chosen by the plane, unique per session) on the session's
        /// current target (round 18: set by FORWARD, in `request` or deferred in `piece`; none yet = FAULT), over `carrier` with credential mode `outbound`. Followed by H_METHOD, H_PATH,
        /// UP_SCOPE?, PAIR*, UP_BODY*/UP_MSG*, UP_END?. CARRIER_RTC (round 27): no H_METHOD/H_PATH/body; PAIR* =
        /// the opening, either exactly one `mirror` = the decimal number of this session's RV_ACCEPT client
        /// exchange (core offers that caller leg's lines mirrored, once they have settled), or ≥ 1 lines
        /// `media` = <kind> then `channel` = <label>, in offer order; anything else is FAULT. Core dials a
        /// datagram session with that opening and answers P_RENDEZVOUS with the local offer (§12.13).
        pub struct UpNew {
            pub exchange: u32,
            pub carrier: u32,
            pub outbound: u32,
            pub _r: u32,
        }
        /// Tail = one message (or fragment) of a duplex session. flags = MSG_*.
        pub struct MsgRec {
            pub flags: u32,
            pub _r: u32,
        }
        /// A message on any exchange (client side 0, an upstream exchange, or a rendezvous exchange), on
        /// `stream` (0 for single-stream carriers; media/data-channel id for rendezvous). Tail = payload.
        pub struct ExMsg {
            pub exchange: u32,
            pub flags: u32,
            pub stream: u64,
        }
        /// Tail = key. LK_PREFIX: list up to `limit` keys with that prefix. LK_CALLER: key is scoped to the
        /// request's verified subject (core adds the scope; the plane never sees it). Round 12, LK_CHAIN (not
        /// with LK_PREFIX): read the host chain named by the key; the tail is the chain key followed by 8 bytes,
        /// `after` (u64 LE, 0 = from the first entry). Answer: up to `limit` LOOKUP_HITs, entries in append
        /// order after `after`, each with key = chain key ‖ seq (u64 BE) and value = the entry exactly as
        /// appended, every one verified by core before it is handed over; then exactly one CHAIN_STATE.
        pub struct LookupRec {
            pub flags: u32,
            pub limit: u32,
        }
        /// Round 12, core-built, after the hits of one LK_CHAIN LOOKUP. len = entries the chain holds;
        /// broken_at = 0 when every entry up to `len` verified, else the first seq that failed verification or
        /// is missing (a missing tail entry included); hits stop before it.
        pub struct ChainState {
            pub lookup: u32,
            pub _r: u32,
            pub len: u64,
            pub broken_at: u64,
        }
        /// Core-built, one per hit. `lookup` = 0-based index of the LOOKUP in the answer. Tail = key then value.
        pub struct LookupHit {
            pub lookup: u32,
            pub key_len: u32,
        }
        /// Tail = key (key_len) then value. flags = LK_CALLER? | LK_CHAIN?. ttl_s 0 = no expiry (round 12; a
        /// non-zero value is clamped to core's records maximum, §12.5): a plane keeps an active task with 0
        /// and re-stores it with a TTL once terminal. Round 12, LK_CHAIN: append `value` (≤ 64 KiB) as the
        /// next entry of the host chain named by `key`; core assigns the sequence (1, 2, ...), frames it
        /// length-prefixed, links it into the chain's hash under the instance's namespace and scope, and
        /// seals it, exactly as kernel host_chains.rs does today; ttl_s must be 0 (else P_STORE_FAILED). Not
        /// allowed inside COMMIT. A DELETE of a key drops its plain record and its chain.
        pub struct StoreRec {
            pub flags: u32,
            pub key_len: u32,
            pub ttl_s: u64,
        }
        /// Tail = nested: H_METHOD, PUSH_URL, PAIR*, BODY. Core delivers it (egress, retry, backoff,
        /// durable queue) until `ttl_s` passes; the plane never learns the outcome except via LOOKUP of its
        /// own records.
        pub struct PushRec {
            pub ttl_s: u64,
        }
        pub struct WakeAt {
            pub mono_ns: u64,
        }
        /// A core decision for the client: status core chose (clamped 400..=599), code = a generic R_*/F_*
        /// (< 0x100; never another kind's code, §12.15), tail = core-written UTF-8 text (≤ 300 bytes).
        pub struct RefusalRec {
            pub status: u32,
            pub code: u32,
        }
        /// Billable usage. `amount` × 10^-`scale` units of the declared class (D_USAGE_CLASS); scale 0..=9.
        /// source = SRC_*. Tail = class text (`[a-z0-9_.:]{1,64}`). Core maps it to the ledger (§12.4).
        /// Round 11: **cumulative**. A USAGE states the session's running total for (class, source) so
        /// far; a later USAGE for the same (class, source) in any answer of the same session replaces it,
        /// never adds. Core posts only the last value per (class, source), once, when the session ends
        /// (`end`, or core's cancel rule of §12.4), so a plane may repeat it on every `piece`.
        pub struct UsageRec {
            pub amount: u64,
            pub scale: u32,
            pub source: u32,
        }
        /// Describe: one billable class this plane may report. unit = UNIT_*. expected_units = the amount
        /// of this class one request is expected to use when the plane states no EXPECT for it (NaN = no
        /// default: the class is left out of candidate cost recipes). Tail = class text.
        pub struct UsageClassRec {
            pub unit: u32,
            pub _r: u32,
            pub expected_units: f64,
        }
        /// Round 15, DA_FAMILY head: `trim_start` 1 = core's binding trims leading whitespace from a key of
        /// this family before presenting it; 0 = verbatim. Tail = nested TEXT prefix, TEXT header.
        pub struct DaFamilyRec {
            pub trim_start: u32,
            pub _r: u32,
        }
        /// The outcome of one upstream attempt, stated as a fact for core to decide on (185). verdict =
        /// ATT_*; class = FC_* (from the dialect body and the operator's `error_map`, not only the status);
        /// retry_after_s = what the upstream asked (body or header), 0 = none. Tail = operator-only reason text
        /// (scrubbed, audited, never shown to a client). Answer of `upstream` (ATT_DECLINE only) or of the
        /// `piece(FROM_UPSTREAM, P_HEAD | P_BODY | P_END)` that let the plane classify the attempt.
        pub struct AttemptRec {
            pub verdict: u32,
            pub class: u32,
            pub retry_after_s: u64,
        }
        /// One compliance row for core's audit chain, written under the request's verified principal by core.
        /// verdict = AUDIT_*. Tail = action (action_len bytes, `[a-z0-9_.:]{1,64}`, e.g. `agent.call`,
        /// `tool.call`), then resource text (≤ 256 bytes, scrubbed).
        pub struct AuditRec {
            pub verdict: u32,
            pub action_len: u32,
        }
        /// "Create, reattach or close usage-observation custody" (today's ScopeRequest, busbar-contract
        /// abi/sdk/plane/observation.rs:22-70). op = OBS_CREATE | OBS_ATTACH | OBS_CLOSE. Tail = nested
        /// OBS_SCOPE_ID (32 bytes; ATTACH, CLOSE), OBS_REQUIRE* (class text: each must be priced in the
        /// original binding before paid work, ≤ 64). Answered by OBS_SCOPE_ANS (P_OBSERVED).
        pub struct ObsScopeRec {
            pub check: u32,
            pub op: u32,
        }
        /// Core-built. status = OBS_READY | OBS_CLOSED | OBS_PENDING | OBS_REFUSED. Tail = the 32-byte scope id
        /// (READY, CLOSED): opaque custody, possession grants nothing; core rebinds it only to the original
        /// authenticated principal on ATTACH.
        pub struct ObsScopeAns {
            pub check: u32,
            pub status: u32,
        }
        /// One owned usage observation (today's Observation, observation.rs:219-260). state = OBS_PROVISIONAL
        /// (evidence only, never an additive charge) | OBS_FINAL (authoritative component totals).
        /// rated_subject = index into core-approved accounting subjects, 0 = the serving subject.
        /// revision_order = authenticated strictly increasing order (0 with no OBS_REVISION). Tail = nested
        /// OBS_SCOPE_ID (32), OBS_EVENT (bytes ≤ 128), OBS_COMPONENT (bytes ≤ 128), OBS_REVISION? (identity
        /// bytes ≤ 128), OBS_COUNT* (UsageRec + class text, declared classes only), OBS_EVIDENCE? (≤ 256).
        /// Answered by OBS_RECEIPT (P_OBSERVED). Classes counted here must not also be sent as USAGE for the
        /// same event: core drops such USAGE and audits `plane_usage_double`.
        pub struct ObserveRec {
            pub check: u32,
            pub state: u32,
            pub rated_subject: u32,
            pub _r: u32,
            pub revision_order: u64,
        }
        /// Core-built. status = OBS_ACCEPTED (durable; tail = receipt bytes ≤ 256, quarantined evidence
        /// included) | OBS_PENDING (the commit may have applied: keep the scope and intent for
        /// reconciliation, never issue another paid create, never substitute zero usage) | OBS_REFUSED.
        pub struct ObsReceipt {
            pub check: u32,
            pub status: u32,
        }
        /// "Does the caller hold this grant?" Tail = grant name text (operator vocabulary, e.g.
        /// `mcp_tool:search`, `pool:realtime`). `check` = plane-chosen id echoed in ENTITLE_ANS.
        pub struct EntitleRec {
            pub check: u32,
            pub _r: u32,
        }
        /// Core-built answer to one ENTITLE: granted = 1 or 0.
        pub struct EntitleAns {
            pub check: u32,
            pub granted: u32,
        }
        /// A far-end session description. RV_ACCEPT: a client brought this offer; core creates a media session
        /// accepting it as client exchange `exchange`. RV_REMOTE: the far end's answer for upstream exchange
        /// `exchange` opened with CARRIER_RTC. Tail = description text (SDP).
        pub struct RendezvousRec {
            pub exchange: u32,
            pub flags: u32,
        }
        /// "Mint a core-sealed ticket bound to this request's verified subject". Tail = nested MT_SCOPE (text),
        /// MT_AUDIENCE (text: the route class it is good for, `ticket`), round 15: MT_PREFIX (text ≤ 16 bytes of
        /// `[A-Za-z0-9_-]`, the client-facing prefix, e.g. `ek_`) and MT_RECORD (bytes ≤ `MAX_TICKET_RECORD`
        /// = 64 KiB, stored by core with the ticket and handed back as `PlaneReq.ticket_record`), all optional.
        /// ttl_s clamped by core. Round 15: flags = MINT_ONCE? (single-use: core consumes the ticket when it
        /// admits a request, on every replica; a second presentation is refused R_REPLAYED). MINTED answers
        /// only once the ticket (and its record) is durably stored.
        pub struct MintRec {
            pub check: u32,
            pub flags: u32,
            pub ttl_s: u64,
        }
        /// Core-built. status 0 = minted (tail = ticket text, opaque to the plane), else a REFUSED code.
        pub struct MintedRec {
            pub check: u32,
            pub status: u32,
            pub expires_at_s: u64,
        }
        /// "Sign this with the host's key" (core picks key, alg and kid). flags = SIGN_JWS_COMPACT (tail =
        /// payload bytes; answer = compact JWS) or SIGN_JWS_DETACHED (tail = payload; answer = nested
        /// SG_PROTECTED + SG_SIGNATURE, the JWS JSON pieces).
        pub struct SignRec {
            pub check: u32,
            pub flags: u32,
        }
        /// Core-built. status 0 = signed (tail as SignRec.flags says), else a REFUSED code.
        pub struct SignedRec {
            pub check: u32,
            pub status: u32,
        }
        /// A caller connection to a configured upstream (per-caller outbound credential, §12.12).
        /// op = CONNECT_BEGIN | CONNECT_STATUS | CONNECT_REVOKE. Tail = nested CN_UPSTREAM (configured upstream
        /// name), CN_RETURN_TO? (BEGIN: where core sends the browser after consent).
        pub struct ConnectRec {
            pub check: u32,
            pub op: u32,
        }
        /// Core-built. state = CONN_NONE | CONN_READY | CONN_PENDING | CONN_REFUSED. BEGIN: tail = the URL to
        /// send the caller to (the plane renders the redirect); otherwise no tail.
        pub struct ConnectAns {
            pub check: u32,
            pub state: u32,
        }
        /// The session outlives its client response: core keeps driving its upstream exchanges, WAKE_AT and
        /// FROM_CORE pieces until FINISH or `ttl_s` (clamped) passes, then calls `end`. Tail = signal key
        /// (may be empty): a SIGNAL with that key from any session of this instance **in this process**
        /// reaches this one (round 20: never another replica's; state other replicas must see goes through
        /// records, COMMIT with REC_PRED, read back by LOOKUP on WAKE_AT).
        /// Round 18: keys are not unique; a SIGNAL or a DX_BROADCAST demux (§12.19) reaches every session
        /// registered under the key. A session whose client response is still open (a listen stream) may
        /// DETACH to register its key; its client side stays open until it ends it or the client goes.
        pub struct DetachRec {
            pub ttl_s: u64,
            pub flags: u32,
            pub _r: u32,
        }
        /// Deliver `piece(FROM_CORE, 0, P_SIGNAL, tail)` to every detached session of this instance registered
        /// under the key (round 18: every, not one; today's keys are unique per task, so nothing changes for them) (flags LK_CALLER: only within the same verified subject). Tail = key. No such session:
        /// dropped silently (the plane learns nothing about other sessions). **Round 20: instance-local, this
        /// process only.** A SIGNAL never crosses replicas and is best-effort (a full session channel drops
        /// it), so it may only shorten a wait; anything a verb on another replica must change (MCP
        /// `tasks/cancel`, `tasks/update`) is a COMMIT on the record the session polls (§8.6 mapping row).
        pub struct SignalRec {
            pub flags: u32,
            pub _r: u32,
        }
        /// "Commit these record changes atomically" (§12.5). Tail = nested generic REC_PRED*, REC_PUT*,
        /// REC_DEL* (REC_CALLER = the request subject's scope). Answered by COMMITTED (P_COMMITTED).
        pub struct CommitRec {
            pub check: u32,
            pub _r: u32,
        }
        /// Core-built. outcome = commit::APPLIED | CONFLICT (then `failed` = index of the first failed
        /// predicate) | 0 with `status` = a REFUSED code (quota, size, store unavailable). Nothing applied unless APPLIED.
        pub struct CommittedRec {
            pub check: u32,
            pub outcome: u32,
            pub failed: u32,
            pub status: u32,
        }
        /// "I observed this counterparty offering these items" (§12.14). Tail = nested TR_PARTY (text: a
        /// configured upstream name), TR_CATALOG? (32 bytes: SHA-256 of the whole listing), TR_ITEM* (pair
        /// shape: item name → 32-byte SHA-256 digest the plane computed from what the upstream sent).
        /// No answer: the trust book records it (a sighting that drifts from the approval quarantines).
        pub struct SightRec {
            pub flags: u32,
            pub _r: u32,
        }
        /// "Does the trust book let this serve?" op = TRUST_SERVES (tail: TR_PARTY, TR_ITEM? pair name →
        /// digest, empty digest = its last sighting) or TRUST_STATE (tail: TR_PARTY). **Round 7**: op =
        /// TRUST_VERIFY (tail: TR_PARTY, TR_PAYLOAD (exactly the bytes signed, before encoding), TR_SIGNATURES
        /// (the document's signatures as written: a JSON array of `{protected, signature}` objects; empty =
        /// none)): "check these detached signatures against the root core holds for this counterparty"
        /// (today's `trust.verify`, busbar-contract abi/host/service.rs:832-848). The plane never sees the root
        /// key, never chooses the algorithm (the root's key selects it) and never decides authenticity.
        /// Answered by TRUST_ANS.
        pub struct TrustRec {
            pub check: u32,
            pub op: u32,
        }
        /// Core-built. verdict = DISTRUST_* (TRUST_SERVES/TRUST_STATE) or SIGNED_* (TRUST_VERIFY).
        /// TRUST_STATE: tail = nested TR_ITEM_STATE*. TRUST_VERIFY with SIGNED_ALGORITHM or SIGNED_CRITICAL:
        /// tail = the algorithm or critical member the signature named (UTF-8, ≤ 128 bytes, core-cut; today's
        /// `into` bytes), so the plane can render it in its dialect; empty otherwise.
        pub struct TrustAns {
            pub check: u32,
            pub verdict: u32,
        }
        /// One item of a TRUST_STATE answer. flags = TS_APPROVED | TS_SIGHTED. Tail = name (name_len), then
        /// the approved digest (32, if TS_APPROVED), then the last sighted digest (32, if TS_SIGHTED).
        pub struct TrustItemState {
            pub verdict: u32,
            pub flags: u32,
            pub name_len: u32,
            pub _r: u32,
        }
        /// Attach this session's `exchange` to the core-owned long-lived channel for the current target's
        /// upstream and tail key (text, ≤ 128 bytes). carrier = CARRIER_STDIO (one child per upstream and
        /// key) or CARRIER_HTTP (one held request, its head records follow: H_METHOD, H_PATH, PAIR*);
        /// framing = CH_FRAME_*; flags = CH_PER_CALLER (one channel per verified subject) | CH_SERIAL (core
        /// releases one session's message only after the previous one's reply was demuxed; round 18, exactly:
        /// core writes one MSG_ASK at a time, the next only after the DEMUX with DX_FINAL for the previous one;
        /// an EX_MSG without MSG_ASK, a reply or a notification, is written at once and never waits). Answered by a
        /// piece(FROM_CORE, exchange, P_CHANNEL, CH_ATTACH). Messages to the channel are EX_MSG on `exchange`;
        /// messages from it arrive as piece(FROM_UPSTREAM, exchange, P_TEXT|P_FIN, message).
        pub struct ChanRec {
            pub exchange: u32,
            pub carrier: u32,
            pub flags: u32,
            pub framing: u32,
        }
        /// Core-built (P_CHANNEL). generation = the channel's incarnation (a restarted child is a new one);
        /// slot = this attachment's correlation number, unique within the generation (the plane puts it in
        /// its wire ids, e.g. JSON-RPC `"<slot>.<n>"`, and `demux` reads it back); greet = 1: this session
        /// must run the protocol greeting (MCP `initialize`) and answer CH_READY before any other session's
        /// message is released; until then every inbound message goes to this session. Tail = the greeting
        /// session's CH_READY tail (greet = 0), e.g. the legacy SSE `endpoint` or server capabilities.
        pub struct ChanAttach {
            pub generation: u64,
            pub slot: u64,
            pub greet: u32,
            pub _r: u32,
        }
        /// `demux` answer (at most one per message): where core delivers this inbound channel message.
        /// flags = DX_RESIGHT (the counterparty announced a change; core schedules a sighting probe), with any
        /// route below. slot ≠ 0: to the attachment holding `slot` in the current generation, as
        /// piece(FROM_UPSTREAM, exchange, P_TEXT|P_FIN, message); with DX_FINAL (round 18) it is the reply that
        /// completes that attachment's oldest open MSG_ASK (the CH_SERIAL release point). Round 18, slot = 0 with:
        /// - DX_OUTSTANDING: a message the counterparty sent unbidden that belongs to "the call now asking"
        ///   (an MCP stdio member's sampling, elicitation or roots request: its id is the server's, so it carries
        ///   no slot). Core delivers it, never as a reply, to the attachment **first in the channel's ask line**:
        ///   the oldest attachment of the current generation with an MSG_ASK not yet completed by DX_FINAL (under
        ///   CH_SERIAL, the one released ask; today's plane-mcp `first_in_line`). Tail (optional, ≤ 4,096 bytes) =
        ///   the fallback core writes to the channel, framed per CH_FRAME_*, when the line is empty (the plane's
        ///   own protocol refusal, e.g. a JSON-RPC error under the server's id); empty tail = dropped and counted.
        /// - DX_BROADCAST: a message for every listener (MCP `notifications/resources/updated`). Tail = key
        ///   (1..=128 bytes, the plane's choice). Core delivers piece(FROM_CORE, 0, P_SIGNAL | P_TEXT, message) to
        ///   every session of this plane instance registered under the key by DETACH (on a CH_PER_CALLER channel,
        ///   only sessions of the channel's subject), at most MAX_FANOUT, each on its bounded session channel (a
        ///   full one drops for that session and counts); the plane learns nothing about the others.
        /// - neither: dropped (audited at debug), as before.
        /// slot ≠ 0 with DX_OUTSTANDING or DX_BROADCAST, both of those together, DX_FINAL without a slot, a tail on
        /// a slot answer, a DX_BROADCAST key outside 1..=128 bytes or a fallback over 4,096 bytes = FAULT.
        pub struct DemuxRec {
            pub slot: u64,
            pub flags: u32,
            pub _r: u32,
        }
        /// Round 10, "write this on line carrier `carrier`" (§12.23), outside any response. Tail = bytes (one
        /// or more `\n`-separated lines, no trailing terminator needed). Core writes the tail and one `\n` to
        /// that carrier, in answer order and, in a request answer, before that request's own response line.
        /// A carrier that has ended or that another instance owns drops it (`plane_emit_dropped_total`); the
        /// plane learns that a carrier ended only from admin(ADMIN_CARRIER_END).
        pub struct EmitRec {
            pub carrier: u64,
        }
        /// Round 10, durable paid work (§12.24). op = WORK_OPEN (tail: nested WK_TARGET, the path + query of
        /// the poll core will deliver; it must match one of this plane's ROUTE_RECOVERY routes) | WORK_FIND
        /// (tail: WK_REF) | WORK_SETTLE (tail: WK_REF). Core binds the row to the request's verified principal
        /// (AUTH_PRINCIPAL identity, or the restored principal of an RQ_RECOVERY request); possession of a
        /// reference grants nothing to another principal. Answered by WORK_ANS (P_WORK), after the store commit.
        pub struct WorkRec {
            pub check: u32,
            pub op: u32,
        }
        /// Core-built. status 0 = done, else a generic REFUSED code (R_UNSUPPORTED: core cannot recover here,
        /// no store or no recovery runtime, §12.24; R_DENIED: no verified principal, or a reference this principal does not own;
        /// R_INVALID: a target on no recovery route; R_NOT_FOUND: an unknown reference; R_RATE_LIMITED: the
        /// instance's live-work cap). state = WORK_LIVE |
        /// WORK_SETTLED (0 when refused). Tail = nested WK_REF (OPEN, FIND), then WK_TARGET (FIND).
        pub struct WorkAns {
            pub check: u32,
            pub status: u32,
            pub state: u32,
            pub _r: u32,
        }
        /// Round 16, "judge this destination for me" (185, I3): one general intent for any destination text a
        /// plane meets in content it does not dial itself (an MCP `tools/call` argument naming a URL or host, an
        /// A2A push-callback URL a client sets, any later case): never an MCP- or A2A-specific shape. Tail = the
        /// destination as the content names it (an absolute URL, or `host[:port]`; UTF-8, ≤ 2,048 bytes, else
        /// the answer is DEST_NO_HOST). class = the `egress::*` class whose rules apply (today's `egress_class`,
        /// same five numbers; > 4 is FAULT BadRecords). flags = JUDGE_RESOLVE? | JUDGE_REFUSE_PRIVATE? (today's
        /// DEST_RESOLVE and DEST_REFUSE_PRIVATE, same bits; any other bit is FAULT BadRecords). Core runs its
        /// one destination guard on it (§12.1: connector `GuardJudge`, the operator's `Destinations` and
        /// `advanced.allow_destinations`, the metadata and obfuscation checks; with JUDGE_RESOLVE also the DNS
        /// resolution and every answered address, the node's own ports included), dials nothing, and answers
        /// JUDGE_ANS (P_JUDGED). Allowed in `request` and `piece` answers only (BadRecords elsewhere).
        pub struct JudgeRec {
            pub check: u32,
            pub class: u32,
            pub flags: u32,
            pub _r: u32,
        }
        /// Core-built. verdict = DEST_* (today's `dest.judge` verdicts, same numbers). No tail: the plane never
        /// learns a resolved address, the matched rule or another destination's state; it renders the verdict
        /// in its own protocol (an MCP tool error, an A2A push-config refusal in the client's error text).
        pub struct JudgeAns {
            pub check: u32,
            pub verdict: u32,
        }
        }
        tags {
            /// to client: RESPOND (head; followed by PAIR* headers), BODY* (byte stream) or MSG* (framed), END.
            RESPOND = 0x0100;
            BODY = 0x0101;
            END = 0x0102;
            /// Round 8, to client: TRAILERS (empty body), then PAIR* trailer fields, then END. At most one per
            /// response, after RESPOND (and any BODY*/MSG*) and immediately before END. Generic pairs: a gRPC plane
            /// sends `grpc-status`, `grpc-message`, `grpc-status-details-bin` here (today's EMIT_FINAL_STATUS),
            /// including a non-OK status after messages were sent. Core hands them to the client transport as
            /// `emit(E_TRAILERS, PAIR*)` (§8.7, §11.3); with no BODY*/MSG* before it on an HTTP/2 carrier, core
            /// sends head + trailers as one HEADERS frame with END_STREAM (gRPC trailers-only).
            TRAILERS = 0x0148;
            /// intent: FORWARD, then wants as FACT/FACT_TEXT (W_*).
            FORWARD = 0x0103;
            /// upstream exchange 0 (answer to `upstream`/`probe`): UP_CARRIER?, H_METHOD, H_PATH, UP_SCOPE?,
            /// PAIR*, UP_BODY. Mid-stream: UP_BODY*, UP_MSG*, UP_END, UP_CUT. 0x0107..=0x0109 are retired.
            UP_BODY = 0x0104;
            UP_END = 0x0105;
            UP_CUT = 0x0106;
            /// further upstream exchanges (MCP client ladder, list-then-call checks, a2a gRPC vs HTTP per attempt).
            UP_NEW = 0x010A;
            /// framed duplex messages, to the client (exchange 0) and upstream (the session's exchange 0).
            MSG = 0x010B;
            UP_MSG = 0x010C;
            /// core records, the plane's own namespace (§12.5). LOOKUP_HIT is core-built input only.
            LOOKUP = 0x010D;
            LOOKUP_HIT = 0x010E;
            STORE = 0x010F;
            DELETE = 0x0110;
            /// plane-originated delivery (A2A push notifications). PUSH_URL is text, nested in PUSH only.
            PUSH = 0x0111;
            PUSH_URL = 0x0112;
            /// per-session timer (keepalives, protocol timeouts).
            WAKE_AT = 0x0113;
            /// `render` inputs: REFUSAL (RefusalRec + text) and CAT_MODEL* (text, model names core shows).
            REFUSAL = 0x0114;
            CAT_MODEL = 0x0115;
            /// carrier, per-call down-scope (text, space-separated). Round 22: a fact about the call, stated
            /// whenever the plane derives one; core hands it to auth `outbound` as O_SCOPE only for a STYLE_SCOPE
            /// binding and drops it otherwise (the plane never learns which).
            UP_CARRIER = 0x0116;
            UP_SCOPE = 0x0117;
            /// billable usage, cumulative per (class, source) (any answer; the last one counts; UsageRec).
            USAGE = 0x0118;
            /// core-resolved intents and their core-built answers (delivered as FROM_CORE pieces).
            ENTITLE = 0x0119;
            ENTITLE_ANS = 0x011A;
            RENDEZVOUS = 0x011B;
            EX_MSG = 0x011C;
            MINT = 0x011D;
            MINTED = 0x011E;
            SIGN = 0x011F;
            SIGNED = 0x0120;
            CONNECT = 0x0121;
            CONNECT_ANS = 0x0122;
            /// session lifetime.
            DETACH = 0x0123;
            SIGNAL = 0x0124;
            FINISH = 0x0125;
            /// nested texts.
            MT_SCOPE = 0x0126;
            MT_AUDIENCE = 0x0127;
            CN_UPSTREAM = 0x0128;
            CN_RETURN_TO = 0x0129;
            /// Round 15: nested in MINT only.
            MT_PREFIX = 0x014F;
            MT_RECORD = 0x0150;
            SG_PROTECTED = 0x012A;
            SG_SIGNATURE = 0x012B;
            /// atomic record commit (intent) and its core-built answer.
            COMMIT = 0x012C;
            COMMITTED = 0x012D;
            /// trust book (§12.14): SIGHT intent, TRUST intent and its answer, nested pieces.
            SIGHT = 0x012E;
            TRUST = 0x012F;
            TRUST_ANS = 0x0130;
            TR_PARTY = 0x0131;
            TR_ITEM = 0x0132;
            TR_CATALOG = 0x0133;
            TR_ITEM_STATE = 0x0134;
            /// Round 7, TRUST_VERIFY pieces (BYTES shape): the signed payload and the signatures array.
            TR_PAYLOAD = 0x0146;
            TR_SIGNATURES = 0x0147;
            /// shared upstream channels (§12.19): CHANNEL intent (ChanRec + key, then head records for HTTP),
            /// CH_READY (U32Rec exchange; tail after it: nested TEXT handed to later attachers), DEMUX answer.
            CHANNEL = 0x0135;
            CH_READY = 0x0136;
            DEMUX = 0x0137;
            /// per-attempt outcome (AttemptRec + reason), compliance audit row (AuditRec + action + resource).
            ATTEMPT = 0x0138;
            AUDIT = 0x0139;
            /// `request` answer: expected usage of one class for this request (UsageRec + class text; source
            /// must be SRC_ESTIMATED). Core prices it per candidate into C_COST_TERM (§8.4). Plane-local.
            EXPECT = 0x013A;
            /// usage-observation custody (§12.4): intents, their core-built answers, nested pieces.
            OBS_SCOPE = 0x013B;
            OBS_SCOPE_ANS = 0x013C;
            OBSERVE = 0x013D;
            OBS_RECEIPT = 0x013E;
            OBS_SCOPE_ID = 0x013F;
            OBS_EVENT = 0x0140;
            OBS_COMPONENT = 0x0141;
            OBS_REVISION = 0x0142;
            OBS_COUNT = 0x0143;
            OBS_EVIDENCE = 0x0144;
            OBS_REQUIRE = 0x0145;
            /// Round 10: EMIT (EmitRec + bytes, §12.23); WORK intent, its core-built answer and its nested
            /// texts (WK_TARGET: path + query, ≤ 512 bytes; WK_REF: reference text, ≤ 128 bytes; §12.24).
            EMIT = 0x0149;
            WORK = 0x014A;
            WORK_ANS = 0x014B;
            WK_TARGET = 0x014C;
            WK_REF = 0x014D;
            /// Round 12: core-built ChainState after an LK_CHAIN LOOKUP's hits (P_LOOKUP).
            CHAIN_STATE = 0x014E;
            /// Round 16: the destination-judge intent (JudgeRec + destination text) and its core-built answer.
            JUDGE = 0x0151;
            JUDGE_ANS = 0x0152;
            /// R6a (#257, IF r35): core-built P_CHANNEL answer: `ChanAttach` + the CH_READY tail, one record.
            CH_ATTACH = 0x0153;
            /// describe: D_ROUTE*, D_DIALECT* (text: upstream dialects this plane can encode), D_TICK_S (U64Rec:
            /// the period core calls admin(ADMIN_TICK); absent = never), D_USAGE_CLASS* (UsageClassRec + class).
            /// Round 13: D_PROVIDER_SCHEMA (UTF-8 JSON Schema, the D_SCHEMA dialect) = the keys this plane owns in a
            /// `providers:` entry; at most one (§8.6 provider keys).
            /// Round 14, **re-cut in round 15 (I2/235/236)**: D_DIALECT_AUTH* = the dialect's native outbound
            /// credential presentation, at most one per D_DIALECT word, stated **only in core-defined generic
            /// fields** (no JSON, no plugin settings key, no plugin-written text). Nested, in this order:
            /// TEXT dialect (one of this image's D_DIALECT items); TEXT presentation, one of core's
            /// `PRESENT_*` words below; then that presentation's fields:
            /// - `PRESENT_HEADER` ("header"): DA_KEY_HEADER? (TEXT, the header the operator's key travels in;
            ///   absent = `Authorization: Bearer`), DA_OWN_HEADER? (TEXT, the header for the operator's own key
            ///   when it differs), DA_PASSTHROUGH_HEADER? (TEXT, a passthrough caller's credential; absent =
            ///   bearer), DA_FAMILY* (DaFamilyRec + TEXT key prefix + TEXT header, empty = bearer: a key whose
            ///   text starts with the prefix travels in that header).
            /// - `PRESENT_SIGN` ("request-signature"): DA_SIGN_SERVICE (TEXT, the signing service name), DA_REGION_AFTER*
            ///   (TEXT, a DNS label of the upstream host whose next label is the signing region),
            ///   DA_REGION_DEFAULT (TEXT, the region when no such label exists).
            /// Every TEXT is ≤ 128 bytes of `[A-Za-z0-9._-]` (header names lowercase), else DescribeInvalid. Core
            /// alone reads them (§12.18): it picks the outbound **style word** from its own table
            /// (`CORE_DIALECT_STYLES`), writes the binding's settings in core vocabulary and writes every operator
            /// text itself. The plane never names a style word, an auth plugin or a settings key, and never sees
            /// a credential (it describes how its dialect's upstream expects one, as today's tail `dialect_auth`).
            D_ROUTE = 0x0180;
            D_DIALECT = 0x0181;
            D_TICK_S = 0x0182;
            D_USAGE_CLASS = 0x0183;
            D_PROVIDER_SCHEMA = 0x0185;
            D_DIALECT_AUTH = 0x0186;
            /// Round 15: the nested fields of D_DIALECT_AUTH (only valid inside it; anywhere else FAULT UnknownTag).
            DA_KEY_HEADER = 0x0187;
            DA_OWN_HEADER = 0x0188;
            DA_PASSTHROUGH_HEADER = 0x0189;
            DA_FAMILY = 0x018A;
            DA_SIGN_SERVICE = 0x018B;
            DA_REGION_AFTER = 0x018C;
            DA_REGION_DEFAULT = 0x018D;
            /// Round 8, describe: the OpenAPI path fragment of this plane's ROUTE_ADMIN routes (UTF-8 JSON object:
            /// keys = those routes' path patterns relative to the instance's admin mount, plus an optional
            /// `components` key; values = OpenAPI path items). Required, non-empty and covering exactly the
            /// ROUTE_ADMIN paths when any route has ROUTE_ADMIN; forbidden otherwise (DescribeInvalid). Today's
            /// ADMIN_OPENAPI text, unchanged.
            D_ADMIN_OPENAPI = 0x0184;
            /// Round 23, describe: the request header in which a route's protocol presents its sender's credential
            /// (RouteHeaderRec + TEXT header name, lowercase, ≤ 128 bytes of `[a-z0-9-]`; at most one per D_ROUTE id;
            /// the id must be a declared D_ROUTE whose auth mask holds AUTH_PRINCIPAL or AUTH_OPTIONAL; else
            /// DescribeInvalid). A protocol fact in core vocabulary, like DA_KEY_HEADER (I2): plane-streaming's
            /// `/twilio/{call_id}` states `x-twilio-signature`, because Twilio Media Streams sign there. It names no
            /// auth plugin, style or instance; core alone picks which configured auth instances run (§12.11
            /// "Route credential header").
            D_ROUTE_CRED_HEADER = 0x018E;
        }
        consts {
            REQUIRED: u64 = 0b1111;
            FROM_CLIENT: u32 = 1;
            FROM_UPSTREAM: u32 = 2;
            FROM_CORE: u32 = 3;
        /// piece flags. FROM_CLIENT/FROM_UPSTREAM: HEAD (records: H_STATUS + PAIR*), BODY, END, TRAILERS
        /// (PAIR*), ERROR (upstream failed after the client response began; bytes = one REFUSAL record to
        /// render in-stream), TEXT/BINARY + FIN (one duplex message or fragment; FIN = last fragment).
        /// On a rendezvous or CARRIER_RTC exchange, bytes start with one U64Rec (the stream id).
            P_HEAD: u32 = 1;
            P_BODY: u32 = 2;
            P_END: u32 = 4;
            P_TRAILERS: u32 = 8;
            P_ERROR: u32 = 16;
            P_TEXT: u32 = 32;
            P_BINARY: u32 = 64;
            P_FIN: u32 = 128;
        /// FROM_UPSTREAM P_HEAD bytes: H_STATUS, PAIR*, then core-written generic FACT(FACT_TLS_PIN)? and
        /// FACT(FACT_TLS_CLIENT_ID)? (§4.1) for an upstream with a configured pin / client identity.
        /// FROM_CORE (exchange 0 unless noted): LOOKUP results (LOOKUP_HIT*), a STORE/DELETE not applied
        /// (bytes = the key), the WAKE_AT time passed (empty), ENTITLE_ANS*, MINTED*, SIGNED*, CONNECT_ANS*,
        /// a SIGNAL's key (round 18: with P_TEXT set, the bytes are instead one DX_BROADCAST channel message,
        /// §12.19), the client went away while DETACHed (empty). P_RENDEZVOUS: exchange = the
        /// rendezvous exchange, bytes = the local description text; P_RV_FAILED: bytes = one REFUSAL.
        /// P_COMMITTED: COMMITTED*. P_TRUST: TRUST_ANS*. P_CHANNEL: exchange = the attached exchange,
        /// bytes = exactly one CH_ATTACH record (ChanAttach + tail); a channel that died mid-session arrives as P_ERROR on that exchange.
            P_LOOKUP: u32 = 0x100;
            P_STORE_FAILED: u32 = 0x200;
            P_TIMER: u32 = 0x400;
            P_ENTITLE: u32 = 0x800;
            P_RENDEZVOUS: u32 = 0x1000;
            P_RV_FAILED: u32 = 0x2000;
            P_MINTED: u32 = 0x4000;
            P_SIGNED: u32 = 0x8000;
            P_CONNECT: u32 = 0x1_0000;
            P_SIGNAL: u32 = 0x2_0000;
            P_CLIENT_GONE: u32 = 0x4_0000;
            P_COMMITTED: u32 = 0x8_0000;
            P_TRUST: u32 = 0x10_0000;
            P_CHANNEL: u32 = 0x20_0000;
        /// P_OBSERVED: OBS_SCOPE_ANS* and OBS_RECEIPT*, in intent order. P_EXHAUSTED (exchange 0): core
        /// stopped trying after the plane's ATTEMPT(RETRY|HARD) verdicts (walk exhausted, deadline, or policy);
        /// bytes = one REFUSAL (generic code from §12.15); the plane answers the client now (RESPOND..END),
        /// and may render the last upstream failure it holds in its session, in the client's dialect.
        /// Round 10: P_WORK: WORK_ANS*, in intent order. Round 16: P_JUDGED: JUDGE_ANS*, in intent order.
            P_OBSERVED: u32 = 0x40_0000;
            P_EXHAUSTED: u32 = 0x80_0000;
            P_WORK: u32 = 0x100_0000;
            P_JUDGED: u32 = 0x200_0000;
        /// Target.flags: TGT_SIGHT = a sighting probe (the trust book says this upstream is due): `probe`
        /// encodes the listing call, and `end` answers SIGHT.
            TGT_SIGHT: u32 = 1;
            FWD_STREAM: u32 = 1;
        /// PlaneReq.flags: RQ_PROJECT = add PJ_* facts and one CONVERSATION to the request answer (core sets
        /// it only when a hook on this route needs them). Round 10: RQ_RECOVERY = core originated this request
        /// to recover durable work (§12.24): `work` names it, identity is the restored principal, no client.
        /// Round 13: RQ_AFFINITY = this route's pool has `affinity` configured and core found no key in the
        /// configured `affinity.header_name` header: state W_AFFINITY with FORWARD if the dialect gives one.
            RQ_PROJECT: u32 = 1;
            RQ_RECOVERY: u32 = 2;
            RQ_AFFINITY: u32 = 4;
        /// RouteRec.flags: ROUTE_CATALOG = a model listing; core answers it with render(RENDER_CATALOG).
        /// Round 8: ROUTE_ADMIN = an admin verb. Core mounts it on the **admin router** (`admin_listen`) at
        /// `<this instance's admin mount>` + the path pattern, never on the data listener, behind the existing
        /// admin scope middleware (`required_scope(method, full path)`: read for GET/HEAD, write otherwise), and
        /// merges D_ADMIN_OPENAPI under the same mount into the admin document. A ROUTE_ADMIN route's auth mask
        /// must be exactly AUTH_OPERATOR (DescribeInvalid otherwise); ROUTE_ADMIN with ROUTE_CATALOG is invalid.
        /// Round 10: ROUTE_LINE = this route takes the lines of the process's own stdin/stdout carrier (core's
        /// `serve_lines`, §12.23); methods exactly POST; never mounted on a listener. ROUTE_RECOVERY = core
        /// delivers durable-work polls here (§12.24); methods exactly GET, auth exactly AUTH_PRINCIPAL, never
        /// mounted on a listener (no client can reach it). Neither combines with any other ROUTE_* bit.
        /// Round 13: ROUTE_UPGRADE = a WebSocket upgrade route: methods exactly GET, served by the upgrade
        /// sequence of §12.27 (route, auth and `request` on the HTTP head; the plane's RESPOND(101) commits;
        /// the same session continues on the adopted stream). Combines with no other ROUTE_* bit.
            ROUTE_CATALOG: u32 = 1;
            ROUTE_ADMIN: u32 = 2;
            ROUTE_LINE: u32 = 4;
            ROUTE_RECOVERY: u32 = 8;
            ROUTE_UPGRADE: u32 = 16;
        /// RouteRec.auth bits and PlaneReq.auth values. PRINCIPAL: an auth plugin must verify a principal.
        /// OPTIONAL: verify if credentials are present, else identity empty. PUBLIC: core never authenticates
        /// (the plane may still check a token it minted through MINT; prefer TICKET). TICKET: the credential is
        /// a core-sealed ticket minted by this plane instance for this audience (core verifies, identity =
        /// its subject + scope claims). SIGNED_INGRESS: core verifies the request signature with the route's
        /// configured webhook secret (Standard Webhooks, §12.11). OPERATOR: an operator principal is required
        /// (admin verbs: connect, health). Round 7: **approve is not a plane verb**: approving an item digest
        /// or an authenticity root, and clearing a quarantine, are core admin API only (§12.14).
            AUTH_PRINCIPAL: u32 = 1;
            AUTH_OPTIONAL: u32 = 2;
            AUTH_PUBLIC: u32 = 4;
            AUTH_TICKET: u32 = 8;
        /// Round 15: MintRec.flags.
            MINT_ONCE: u32 = 1;
            MAX_TICKET_RECORD: u64 = 65_536;
            AUTH_SIGNED_INGRESS: u32 = 16;
            AUTH_OPERATOR: u32 = 32;
        /// carriers: a protocol, never a plugin. DEFAULT = the route's configured carrier.
            CARRIER_DEFAULT: u32 = 0;
            CARRIER_HTTP: u32 = 1;
            CARRIER_GRPC: u32 = 2;
            CARRIER_WEBSOCKET: u32 = 3;
            CARRIER_RTC: u32 = 4;
        /// a child process core runs from the upstream's configured command (CHANNEL only).
            CARRIER_STDIO: u32 = 5;
            CH_PER_CALLER: u32 = 1;
            CH_SERIAL: u32 = 2;
            CH_FRAME_NONE: u32 = 0;
            CH_FRAME_NDJSON: u32 = 1;
            CH_FRAME_SSE: u32 = 2;
            DX_RESIGHT: u32 = 1;
            DX_OUTSTANDING: u32 = 2;
            DX_BROADCAST: u32 = 4;
            DX_FINAL: u32 = 8;
            MAX_FANOUT: u32 = 4_096;
            TRUST_SERVES: u32 = 1;
            TRUST_STATE: u32 = 2;
            TS_APPROVED: u32 = 1;
            TS_SIGHTED: u32 = 2;
        /// Round 7: signature check against core's root for the counterparty (§12.14 `TrustBook::verify`).
            TRUST_VERIFY: u32 = 3;
        /// TRUST_VERIFY verdicts (today's SIGNED_*, busbar-contract abi/host/service.rs:854-870, same numbers).
            SIGNED_VERIFIED: u32 = 0;
            SIGNED_NONE: u32 = 1;
            SIGNED_TOO_MANY: u32 = 2;
            SIGNED_MALFORMED_HEADER: u32 = 3;
            SIGNED_ALGORITHM: u32 = 4;
            SIGNED_CRITICAL: u32 = 5;
            SIGNED_MALFORMED_SIGNATURE: u32 = 6;
            SIGNED_NOT_BY_ROOT: u32 = 7;
            SIGNED_MALFORMED_ROOT: u32 = 8;
        /// trust verdicts (today's DISTRUST_*, busbar-contract abi/host/service.rs:747-759, same numbers).
            DISTRUST_NONE: u32 = 0;
            DISTRUST_UNKNOWN: u32 = 1;
            DISTRUST_UNSIGHTED: u32 = 2;
            DISTRUST_QUARANTINED: u32 = 3;
            DISTRUST_NOT_APPROVED: u32 = 4;
            DISTRUST_CHANGED: u32 = 5;
            DISTRUST_UNKNOWN_ITEM: u32 = 6;
        /// outbound credential intent. DEFAULT = whatever the target's configured outbound binding presents,
        /// decided by core (round 21: for a provider attempt `providers.<p>.auth` or its implicit binding,
        /// §12.18; for a configured upstream `upstreams.<name>.auth`, §12.1; neither configured = no
        /// credential; round 22: a binding whose style declared STYLE_CALLER presents the verified caller's
        /// own connection grant, §12.12, and with none held the exchange fails with piece(FROM_UPSTREAM,
        /// P_ERROR, REFUSAL code R_CONNECT_REQUIRED, the generic code of §4.1)); NONE = no credential (e.g. an
        /// unauthenticated discovery call). Round 22: 2 (round 21's OUTBOUND_CALLER) is retired, never reused;
        /// a plane stating it is FAULT BadRecords.
            OUTBOUND_DEFAULT: u32 = 0;
            OUTBOUND_NONE: u32 = 1;
        /// Round 18: MSG_ASK (EX_MSG on a CHANNEL exchange only; anywhere else FAULT): this message expects a
        /// reply from the counterparty (a JSON-RPC request). Core enters the attachment in the channel's ask
        /// line until the DEMUX with DX_FINAL for its slot; under CH_SERIAL it holds the message until the
        /// previous ask completes. Plane-only: transport MSG_* map 1:1 onto TEXT/BINARY/FIN, never ASK.
            MSG_TEXT: u32 = 1;
            MSG_BINARY: u32 = 2;
            MSG_FIN: u32 = 4;
            MSG_ASK: u32 = 8;
            LK_PREFIX: u32 = 1;
            LK_CALLER: u32 = 2;
            LK_CHAIN: u32 = 4;
            RENDER_REFUSAL: u32 = 1;
            RENDER_CATALOG: u32 = 2;
            RV_ACCEPT: u32 = 1;
            RV_REMOTE: u32 = 2;
            SIGN_JWS_COMPACT: u32 = 1;
            SIGN_JWS_DETACHED: u32 = 2;
            CONNECT_BEGIN: u32 = 1;
            CONNECT_STATUS: u32 = 2;
            CONNECT_REVOKE: u32 = 3;
            CONN_NONE: u32 = 0;
            CONN_READY: u32 = 1;
            CONN_PENDING: u32 = 2;
            CONN_REFUSED: u32 = 3;
        /// usage sources (map 1:1 to the ledger's existing sources, §12.4) and units.
            SRC_REPORTED: u32 = 1;
            SRC_ESTIMATED: u32 = 2;
            SRC_FLOOR: u32 = 3;
            UNIT_COUNT: u32 = 1;
            UNIT_TOKENS: u32 = 2;
            UNIT_BYTES: u32 = 3;
            UNIT_MILLISECONDS: u32 = 4;
            UNIT_CHARACTERS: u32 = 5;
        /// 0x100 (round 3's kind code CONNECT_REQUIRED) is retired: it is the generic R_CONNECT_REQUIRED now.
        /// describe fact bits: FB_PROBES = core may call `probe` per member (today's TAIL_PROBES).
            FB_PROBES: u64 = 1;
        /// wants (core reads them to choose candidates; plane-local keys, never forwarded to another kind)
        /// Round 10: W_UPSTREAM (FACT_TEXT = a configured upstream name the plane saw in `Target.upstream`):
        /// core's walk tries only that member and never reroutes; RETRY/HARD then yield P_EXHAUSTED (a
        /// recovery poll must reach the member that holds the paid work, §12.24).
        /// Round 13: W_AFFINITY (FACT_TEXT, ≤ 256 bytes) = the sticky-routing key the plane derived from the
        /// request body in its dialect (e.g. chat's `system`), stated only when the request has RQ_AFFINITY.
        /// Core's walk prefers one stable member per key (the kept far_end.rs:260 rule, §8.6 affinity below).
            W_MODEL: u32 = 0x100;
            W_STREAM: u32 = 0x101;
            W_CAPABILITY: u32 = 0x102;
            W_MAX_TOKENS: u32 = 0x103;
            W_UPSTREAM: u32 = 0x104;
            W_AFFINITY: u32 = 0x105;
        /// protocol facts. 0x201..=0x205 and 0x20A (round 2's token counts and F_REQUESTS) are retired: usage is
        /// USAGE records now. F_PROBE_OK: `end` of a probe session, 1 = the member answered correctly.
            F_MODEL: u32 = 0x200;
            F_TASK_ID: u32 = 0x206;
            F_TOOL: u32 = 0x207;
            F_UPSTREAM_REQUEST_ID: u32 = 0x208;
            F_UPSTREAM_STATUS: u32 = 0x209;
            F_PROBE_OK: u32 = 0x20B;
        /// ATTEMPT verdicts (today's VERDICT_OK/RETRY/HARD numbers, busbar-contract abi/plane/mod.rs:638-642,
        /// plus two). OK = the attempt succeeded: core commits the client response the plane writes. RETRY =
        /// this member failed this request; another may serve it. HARD = this member is down (breaker input
        /// with `class`). RELAY = the caller's own failure (e.g. a passthrough 401/403 or a client error):
        /// no retry, the plane's to-client records in the same answer are the response. DECLINE (`upstream`
        /// answer only) = this plane will not send to this member at all (e.g. no binding the plane speaks);
        /// core moves on without dialling. An answer with RETRY, HARD or DECLINE carries no to-client record
        /// (else FAULT); a `piece(FROM_UPSTREAM)` answer with no ATTEMPT is ATT_OK.
            ATT_OK: u32 = 1;
            ATT_RETRY: u32 = 2;
            ATT_HARD: u32 = 3;
            ATT_RELAY: u32 = 4;
            ATT_DECLINE: u32 = 5;
        /// Failure classes (facts; core maps them, §12.3): CONTEXT_LENGTH drives the walk to a larger
        /// window; BILLING and AUTH mark the member hard-down with that reason; RATE_LIMIT and OVERLOADED use
        /// retry_after_s; CLIENT is never retried.
            FC_NONE: u32 = 0;
            FC_CLIENT: u32 = 1;
            FC_AUTH: u32 = 2;
            FC_RATE_LIMIT: u32 = 3;
            FC_CONTEXT_LENGTH: u32 = 4;
            FC_BILLING: u32 = 5;
            FC_OVERLOADED: u32 = 6;
            FC_SERVER: u32 = 7;
            FC_TIMEOUT: u32 = 8;
            FC_PROTOCOL: u32 = 9;
            FC_CONTENT_POLICY: u32 = 10;
        /// AUDIT verdicts (today's AUDIT_* numbers, abi/plane/mod.rs:674-678).
            AUDIT_APPLIED: u32 = 1;
            AUDIT_REJECTED: u32 = 2;
            AUDIT_DEGRADED: u32 = 3;
            OBS_CREATE: u32 = 1;
            OBS_ATTACH: u32 = 2;
            OBS_CLOSE: u32 = 3;
            OBS_READY: u32 = 1;
            OBS_CLOSED: u32 = 2;
            OBS_PENDING: u32 = 3;
            OBS_REFUSED: u32 = 4;
            OBS_ACCEPTED: u32 = 5;
            OBS_PROVISIONAL: u32 = 1;
            OBS_FINAL: u32 = 2;
        /// Round 10: WORK ops and work states (today's WORK_LIVE/WORK_SETTLED, busbar-contract
        /// abi/host/service.rs:613-615, same numbers).
            WORK_OPEN: u32 = 1;
            WORK_FIND: u32 = 2;
            WORK_SETTLE: u32 = 3;
            WORK_LIVE: u32 = 1;
            WORK_SETTLED: u32 = 2;
        /// Round 16: JudgeRec.flags (busbar-contract abi/host/service.rs:500-504 DEST_RESOLVE/DEST_REFUSE_PRIVATE,
        /// same bits) and JudgeAns.verdict (service.rs:507-523 DEST_*, same numbers; a future verdict is a new
        /// number, never a reuse, and a plane renders an unknown one as a refusal).
            JUDGE_RESOLVE: u32 = 1;
            JUDGE_REFUSE_PRIVATE: u32 = 2;
            DEST_ALLOWED: u32 = 0;
            DEST_SCHEME: u32 = 1;
            DEST_NO_HOST: u32 = 2;
            DEST_METADATA: u32 = 3;
            DEST_OBFUSCATED: u32 = 4;
            DEST_INTERNAL: u32 = 5;
            DEST_PLAINTEXT: u32 = 6;
            DEST_UNRESOLVABLE: u32 = 7;
            DEST_NO_ADDRESSES: u32 = 8;
            ADMIN_CATALOG: u32 = 1;
            ADMIN_HYDRATE: u32 = 2;
            ADMIN_TICK: u32 = 3;
            ADMIN_CARRIER_END: u32 = 4;
            M_REQUEST: u64 = 1 << 0;
            M_UPSTREAM: u64 = 1 << 1;
            M_PIECE: u64 = 1 << 2;
            M_END: u64 = 1 << 3;
            M_REWRITE: u64 = 1 << 4;
            M_RENDER: u64 = 1 << 5;
            M_ADMIN: u64 = 1 << 6;
            M_PROBE: u64 = 1 << 7;
            M_DEMUX: u64 = 1 << 8;
        }
        /// Start one request. Answer (after the shim's TOKEN) is one of: RESPOND+PAIR*+(BODY*|MSG*)+(TRAILERS+PAIR*)?+END
        /// (answered locally); FORWARD + wants (core picks candidates, then calls `upstream`); intents alone
        /// (LOOKUP*, ENTITLE*, JUDGE*, MINT*, SIGN*, CONNECT*, COMMIT*, TRUST*, WORK*, CHANNEL*, RENDEZVOUS: core resolves them and calls `piece(FROM_CORE)`
        /// before anything else, e.g. MCP session, A2A tasks/get, tools/list filtering, the SDP door). With
        /// RQ_PROJECT it also carries PJ_* facts and one CONVERSATION. With FORWARD it may carry EXPECT* (this
        /// request's expected usage per class, for candidate cost recipes). OBS_SCOPE*/OBSERVE* are intents like
        /// LOOKUP (a paid create waits for P_OBSERVED before answering the client). Any answer may add FACT*,
        /// USAGE*, METRIC*, AUDIT*, STORE*, DELETE*, COMMIT*, SIGHT*, PUSH*, WAKE_AT, DETACH, SIGNAL*, EMIT*. Err = no
        /// session (REFUSED/FAILED, no TOKEN; the proxy returns no handle, §10.4). Round 10, a ROUTE_LINE request
        /// (`req.carrier` != 0): body = one line without its terminator; the to-client BODY bytes are written
        /// as one line (core adds `\n`), an empty body writes nothing (a notification, or a line answered only
        /// by EMIT), and the status is not written (the plane states errors in its own protocol).
        sync open fn request(&self, h: &Host, req: &PlaneReq<'_>, body: Bytes<'_>, out: &mut Out<'_>) -> Result<Session, Fail>;
        /// Encode upstream exchange 0 for one attempt. Called once per attempt (core retries and reroutes).
        /// Answer: UP_CARRIER?, H_METHOD, H_PATH, UP_SCOPE?, PAIR*, UP_BODY. Core adds the host (the URL's
        /// authority with the scheme-default port elided, today's transport-http `client_defaults` rule), the
        /// carrier transport's own default lines each the head lacks (round 22: `TransportPort::defaults`, §8.7
        /// `offer`), then the credential (per UP_CARRIER.outbound, from the binding core resolved; the auth
        /// `outbound` call sees and may sign the complete head), and hands the head to the carrier's transport
        /// with core-written H_BUDGET_NS? and H_BODY_LEN? (§3). Or ATTEMPT(ATT_DECLINE, class) alone: this
        /// member is not one the plane will send to; core's walk moves to the next member without dialling.
        sync fn upstream(&self, h: &Host, s: &mut Session, target: &Target<'_>, out: &mut Out<'_>) -> Result<(), Fail>;
        /// Bytes or core events for exchange `exchange` (0 for the client side and most FROM_CORE).
        /// Answer: to the client RESPOND/PAIR*/BODY*/MSG*/TRAILERS/END; upstream UP_BODY*/UP_MSG*/UP_END/UP_CUT; EX_MSG*;
        /// UP_NEW; CHANNEL; CH_READY; RENDEZVOUS; the intents (WORK* and, round 16, JUDGE* included); round 18: FORWARD + wants
        /// (+ EXPECT*), FROM_CORE only, once (the deferred-FORWARD rule below); STORE*, DELETE*, COMMIT*, SIGHT*, PUSH*, WAKE_AT,
        /// FACT*, USAGE*, METRIC*, AUDIT*, DETACH, SIGNAL*, EMIT*, FINISH. Core applies STORE/DELETE/COMMIT in answer order
        /// before its next call on this session; STORE and DELETE are single-key and independent, COMMIT is atomic.
        /// **Attempt rule (exchange 0, before the client response has begun):** the plane classifies the
        /// upstream's head (and, when the class is in the body, the body up to P_END) and either writes the
        /// client response (ATT_OK implied, or ATT_RELAY) or answers ATTEMPT(ATT_RETRY | ATT_HARD, class,
        /// retry_after_s) with no to-client record; it may keep the failure in its session. Core then decides
        /// (§12.3): another attempt (`upstream` with attempt + 1) or `piece(FROM_CORE, 0, P_EXHAUSTED, REFUSAL)`.
        /// Nothing reaches the client until core has decided. After RESPOND, a failure is P_ERROR as before.
        /// **Round 18, deferred FORWARD (at most once per session):** a `piece(FROM_CORE)` answer on a session that
        /// has not forwarded and has not begun its client response may be FORWARD + W_* (FACT/FACT_TEXT) + EXPECT*,
        /// with any of FACT*, USAGE*, METRIC*, AUDIT*, STORE*, DELETE*, COMMIT*, EMIT*, and with no intent and no
        /// to-client record: the route then follows what core resolved for the plane (a LOOKUP(LK_CALLER) hit naming
        /// the model entry that created a stored resource, a WORK_FIND target), e.g. plane-llm's native
        /// Interactions GET/DELETE/cancel of a stored interaction and a create with `previous_interaction_id`
        /// (today's ROUTE_AUTHENTICATED + `authenticated_route`). Core proceeds exactly as after a FORWARD
        /// `request` answer (hooks, `rewrite`, candidates and pricing, `upstream`). A second FORWARD, FORWARD after
        /// RESPOND, FORWARD in a FROM_CLIENT or FROM_UPSTREAM answer, or FORWARD beside an intent = FAULT.
        sync fn piece(&self, h: &Host, s: &mut Session, from: u32, exchange: u32, flags: u32, bytes: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail>;
        /// The request is over (normally, by FINISH, by DETACH ttl, or by a probe's response). Answer: final
        /// FACT*, USAGE*, OBSERVE* (fire-and-record: no P_OBSERVED follows `end`; core still writes them durably
        /// and audits a refusal), AUDIT*, STORE*, DELETE*, PUSH*, EMIT*. The session is consumed. A session core drops without `end`
        /// (abort, timeout, shutdown) is dropped by `cancel` and produces no answer; round 11: core bills it by its own
        /// cancel rule over its own facts and the last cumulative USAGE the session already answered (§12.4).
        sync end fn end(&self, h: &Host, s: Session, out: &mut Out<'_>) -> Result<(), Fail>;
        /// Apply a hook's REWRITE (CONVERSATION JSON) to the request held in the session, in the client's
        /// dialect; the next `upstream` encodes the rewritten request. Called after `request`, before the first
        /// `upstream`. Answer: FACT* or nothing. REFUSED R_INVALID = does not fit; core keeps the original.
        sync fn rewrite(&self, h: &Host, s: &mut Session, conversation: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, s, conversation, out); Err(crate::fail::Fail::unsupported()) }
        /// Sessionless rendering of a core decision in the client's dialect (derived from route, path and
        /// headers). RENDER_REFUSAL: arg = one REFUSAL (auth deny, budget, hook VERB_REJECT, no candidate).
        /// RENDER_CATALOG: arg = CAT_MODEL* for a ROUTE_CATALOG route. Answer (round 9):
        /// RESPOND PAIR* BODY? (TRAILERS PAIR*)? END. A gRPC-dialect refusal answers RESPOND(200) + its PAIR*
        /// head, no BODY, then TRAILERS + `grpc-status`/`grpc-message`/`grpc-status-details-bin` (today's
        /// refusal block); core sends it as one trailers-only HEADERS frame, exactly as for a session (TRAILERS).
        sync fn render(&self, h: &Host, req: &PlaneReq<'_>, what: u32, arg: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, req, what, arg, out); Err(crate::fail::Fail::unsupported()) }
        /// Cold. CATALOG: refresh catalog data (FETCH) into instance state. HYDRATE: arg = stored records the
        /// plane asked core to keep. TICK: every D_TICK_S (RECORD and FETCH allowed); answer PUSH* and (round 10)
        /// EMIT* only. CARRIER_END (round 10, §12.23): arg = U64Rec(carrier): that line carrier has ended (stdin
        /// EOF, a write failure, or shutdown), its line sessions are already ended or cancelled, and the plane
        /// drops its per-carrier state; called once per carrier, answer empty.
        async fn admin(&self, h: &'static Host, op: u32, arg: ChainBytes) -> Result<Reply, Fail> { let _ = (h, op, arg); Err(crate::fail::Fail::unsupported()) }
        /// Health probe of one member (FB_PROBES). Opens a session like `request`; answer (after TOKEN) as
        /// `upstream`: a minimal request in the target's dialect. Core sends it, feeds the response through
        /// `piece(FROM_UPSTREAM, 0, ..)`, then calls `end`, whose answer carries FACT(F_PROBE_OK) and USAGE*.
        /// With TGT_SIGHT the request is the listing call (it may use CHANNEL), and `end` answers SIGHT.
        /// Round 21: in a TGT_SIGHT session only, core follows a same-origin 301/302/303/307/308 on a GET
        /// exchange (≤ 3 hops, each judged by the guard); a cross-origin or fourth redirect reaches `piece` as the
        /// 3xx P_HEAD, unfollowed (§12.14 card fetch). No other session's 3xx is ever followed.
        sync open fn probe(&self, h: &Host, target: &Target<'_>, out: &mut Out<'_>) -> Result<Session, Fail> { let _ = (h, target, out); Err(crate::fail::Fail::unsupported()) }
        /// Sessionless and pure: which attachment does this one inbound channel message (already framed by core
        /// per CH_FRAME_*) belong to? `key` is the channel key the plane chose. Answer: DEMUX, or nothing (= slot 0).
        /// Round 18: DEMUX may route by role instead of slot: DX_OUTSTANDING (the call now asking) or DX_BROADCAST
        /// (every session registered under a key), DemuxRec. Still pure: it reads key and message and names no session.
        sync fn demux(&self, h: &Host, key: Str<'_>, message: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, key, message, out); Err(crate::fail::Fail::unsupported()) }

        extras {
            /// The host side of the plane kind: a typed face over busbar-ffi's `Instance` (IF §10.4).
            /// `live` points into the plugin image and is valid because `inst` holds the image (I13).
            #[cfg(feature = "host")]
            pub struct Proxy {
                inst: std::sync::Arc<crate::host_side::driver::Instance>,
                live: std::sync::Arc<busbar_ffi::host::Instance<Marker>>,
            }

            #[cfg(feature = "host")]
            impl Proxy {
                /// Bind. Done by the loader only, after admit; None when `inst` is not a plane instance.
                pub fn bind(inst: std::sync::Arc<crate::host_side::driver::Instance>) -> Option<Self> {
                    let live = inst.live::<Marker>()?;
                    Some(Proxy { inst, live })
                }

                pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
                    &self.inst
                }

                pub fn request<'o>(
                    &self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    req: &PlaneReq<'_>,
                    body: &[u8],
                ) -> Result<
                    (Option<SessionHandle>, crate::host_side::answer::Answer<'o>),
                    crate::fail::CallError,
                > {
                    #[allow(unused_imports)]
                    use crate::plugin::__rt::Arg;
                    #[allow(unused_imports)]
                    use crate::types::{Bytes, Str};
                    let (session, answer) = crate::host_side::proxy::opener::<Marker>(
                        &self.inst,
                        crate::host_side::proxy::entry(M_REQUEST),
                        buf,
                        |lease| {
                            self.live.open_session2(
                                |vt| &vt.request,
                                Arg::view(req),
                                Arg::bytes(Bytes::new(body)),
                                lease,
                            )
                        },
                    )?;
                    Ok((
                        session.map(|session| SessionHandle {
                            inst: std::sync::Arc::clone(&self.inst),
                            session,
                        }),
                        answer,
                    ))
                }

                pub fn render<'o>(
                    &self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    req: &PlaneReq<'_>,
                    what: u32,
                    arg: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    #[allow(unused_imports)]
                    use crate::plugin::__rt::Arg;
                    #[allow(unused_imports)]
                    use crate::types::{Bytes, Str};
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_RENDER), buf, |lease| {
                        self.live.call3(
                            |vt| &vt.render,
                            (Arg::view(req), Arg::u32(what), Arg::bytes(Bytes::new(arg))),
                            lease,
                        )
                    })
                }

                pub fn admin<'a, N: crate::host_side::needs::Needs>(
                    &'a self,
                    drv: &'a mut crate::host_side::driver::Driver<'a, N>,
                    req: crate::host_side::pool::PooledOut,
                    op: u32,
                ) -> impl core::future::Future<
                    Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
                > + Send
                + 'a {
                    use crate::host_side::proxy;
                    #[allow(unused_imports)]
                    use crate::plugin::__rt::Arg;
                    proxy::chain::<Marker, _, _>(&self.inst, drv, proxy::entry(M_ADMIN), req, move |req, lease| {
                        let _ = req;
                        let (bufs, at) = proxy::staged(req);
                        self.live
                            .start2(
                                |vt| &vt.admin,
                                bufs,
                                |b| (Arg::u32(op), Arg::bytes(b.get(at))),
                                lease,
                            )
                            .into()
                    })
                }

                pub fn probe<'o>(
                    &self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    target: &Target<'_>,
                ) -> Result<
                    (Option<SessionHandle>, crate::host_side::answer::Answer<'o>),
                    crate::fail::CallError,
                > {
                    #[allow(unused_imports)]
                    use crate::plugin::__rt::Arg;
                    #[allow(unused_imports)]
                    use crate::types::{Bytes, Str};
                    let (session, answer) = crate::host_side::proxy::opener::<Marker>(
                        &self.inst,
                        crate::host_side::proxy::entry(M_PROBE),
                        buf,
                        |lease| {
                            self.live.open_session1(|vt| &vt.probe, Arg::view(target), lease)
                        },
                    )?;
                    Ok((
                        session.map(|session| SessionHandle {
                            inst: std::sync::Arc::clone(&self.inst),
                            session,
                        }),
                        answer,
                    ))
                }

                pub fn demux<'o>(
                    &self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    key: &str,
                    message: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    #[allow(unused_imports)]
                    use crate::plugin::__rt::Arg;
                    #[allow(unused_imports)]
                    use crate::types::{Bytes, Str};
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_DEMUX), buf, |lease| {
                        self.live.call2(
                            |vt| &vt.demux,
                            Arg::str(Str::new(key)),
                            Arg::bytes(Bytes::new(message)),
                            lease,
                        )
                    })
                }

            }

            /// One live plane session as the host holds it (IF §10.4): `Send`, not `Sync` and not `Clone`; every
            /// method takes `&mut self`, and its `Drop` is the only cancel (busbar-ffi's `Session`), so a cancel cannot
            /// race a method and two entries on one token need two `&mut` borrows, which the borrow checker refuses (I6).
            #[cfg(feature = "host")]
            pub struct SessionHandle {
                inst: std::sync::Arc<crate::host_side::driver::Instance>,
                session: busbar_ffi::host::Session<Marker>,
            }

            #[cfg(feature = "host")]
            impl SessionHandle {
                pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
                    &self.inst
                }

                pub fn upstream<'o>(
                    &mut self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    target: &Target<'_>,
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    #[allow(unused_imports)]
                    use crate::plugin::__rt::Arg;
                    #[allow(unused_imports)]
                    use crate::types::{Bytes, Str};
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_UPSTREAM), buf, |lease| {
                        self.session.call1(|vt| &vt.upstream, Arg::view(target), lease)
                    })
                }

                pub fn piece<'o>(
                    &mut self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    from: u32,
                    exchange: u32,
                    flags: u32,
                    bytes: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    #[allow(unused_imports)]
                    use crate::plugin::__rt::Arg;
                    #[allow(unused_imports)]
                    use crate::types::{Bytes, Str};
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_PIECE), buf, |lease| {
                        self.session.call4(
                            |vt| &vt.piece,
                            (
                                Arg::u32(from),
                                Arg::u32(exchange),
                                Arg::u32(flags),
                                Arg::bytes(Bytes::new(bytes)),
                            ),
                            lease,
                        )
                    })
                }

                /// The consuming method: the plugin removes the session whatever it answers, so `Drop` has nothing
                /// left to cancel.
                pub fn end<'o>(
                    self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    let SessionHandle { inst, session } = self;
                    crate::host_side::proxy::sync(
                        &inst,
                        crate::host_side::proxy::entry(M_END),
                        buf,
                        |lease| session.end(|vt| &vt.end, lease),
                    )
                }

                pub fn rewrite<'o>(
                    &mut self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    conversation: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    #[allow(unused_imports)]
                    use crate::plugin::__rt::Arg;
                    #[allow(unused_imports)]
                    use crate::types::{Bytes, Str};
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_REWRITE), buf, |lease| {
                        self.session.call1(|vt| &vt.rewrite, Arg::bytes(Bytes::new(conversation)), lease)
                    })
                }

            }
        }
    }
}
