# Voice cross-dialect mapping: OpenAI Realtime ⟷ Gemini Live

This document pairs the two realtime voice dialects the busbar voice plane bridges:

- **OpenAI Realtime API** — WebSocket, flat envelope (`{ "type": ..., ... }`).
- **Gemini Live API** (`BidiGenerateContent`) — WebSocket, tagged-union envelope (the single
  top-level key names the message type, e.g. `{ "setup": {...} }`).

It is the DATA the voice cross-parity conformance leg and the #14-B Gemini codec consume. The
machine-readable companion is [`voice-cross-dialect-map.json`](./voice-cross-dialect-map.json);
every fixture path it names exists under `testing/voice-conformance/fixtures/{openai,gemini}/`.
The **asymmetry table** at the bottom is the honesty contract the cross-parity leg's verdict
checks — same discipline the LLM plane uses for provider-specific fields (drop + warn, never
silently invent).

## Fixture shape notes (accuracy)

- **OpenAI session shape duality.** The primary OpenAI fixtures use the widely-deployed
  `gpt-4o-realtime-preview` **flat** session shape (`session.modalities`,
  `session.input_audio_format`, `session.voice`, `session.max_response_output_tokens`, …) — the
  exact field set this task enumerated. The newer GA `gpt-realtime` (Aug 2025) model **nests**
  these under `session.audio.{input,output}` and renames the fields
  (`output_modalities`, `max_output_tokens`, `audio.input.format`, `audio.output.voice`);
  `openai/session.update.ga_nested.json` captures that variant. The GA model likewise renames the
  streamed output-audio events `response.audio.delta`/`.done` → `response.output_audio.delta`/`.done`.
  The mapping treats these as the same concept; the codec must accept both spellings.
- **Rate tagging.** Gemini tags the PCM sample rate in the blob `mimeType`
  (`audio/pcm;rate=16000` in, `audio/pcm;rate=24000` out). OpenAI carries **no** per-frame format —
  the rate/codec is session-wide. The bridge injects/strips the `mimeType` accordingly.
- Fields the research could not confirm verbatim against the docs are flagged in the JSON map's
  `$schema_note`/`shape_note` and were kept to standard/representative shapes rather than invented.

## Audio format / rate bridge

| Aspect | OpenAI | Gemini | Transform |
|---|---|---|---|
| Container | base64 raw bytes in `audio`/`delta` | base64 raw bytes in `...data`, rate in `mimeType` | pass base64 through; add/remove the `mimeType` |
| Default codec | `pcm16` (16-bit LE PCM) | `audio/pcm` (16-bit LE PCM) | direct |
| Input rate | session-wide (untagged) | `rate=16000` | resample to 16 kHz toward Gemini; strip tag toward OpenAI |
| Output rate | session-wide (untagged), model emits 24 kHz | `rate=24000` | tag 24 kHz toward Gemini |
| Telephony | `g711_ulaw` / `g711_alaw` @ 8 kHz | *(none)* | transcode g711 ⟷ pcm16 or refuse leg — see asymmetry `openai_g711` |

## Concept mapping

| Concept | OpenAI field(s) / fixture | Gemini field(s) / fixture | Transform |
|---|---|---|---|
| Session / setup config | `session.update` — `session.{modalities,instructions,voice,input_audio_format,output_audio_format,turn_detection,tools,tool_choice,max_response_output_tokens}` | `setup` — `setup.{model,generationConfig.responseModalities,systemInstruction,speechConfig…voiceName,tools[].functionDeclarations,realtimeInputConfig,generationConfig.maxOutputTokens}` | instructions⟷systemInstruction.parts[].text; voice⟷prebuiltVoiceConfig.voiceName (name sets differ); modalities[audio,text]⟶ single responseModalities (drop text, warn); tools⟷functionDeclarations, JSON-Schema type casing lower⟷UPPER |
| Session ack / handshake | `session.created` | `setupComplete` (`{}`) | OpenAI echoes resolved session; Gemini sends empty ack — bridge fabricates the missing side |
| User text message | `conversation.item.create` message — `content[].input_text.text` | `clientContent.turns[].parts[].text` + `turnComplete` | text⟷text; OpenAI item standalone, Gemini needs `turnComplete` |
| Input audio frame | `input_audio_buffer.append` — `audio` | `realtimeInput.audio.{mimeType,data}` | base64 passthrough; inject/strip `mimeType` rate |
| Input turn commit | `input_audio_buffer.commit` | `realtimeInput.audioStreamEnd` | explicit only under manual VAD; else implicit both sides |
| Output audio frame | `response.audio.delta` (GA `response.output_audio.delta`) — `delta` | `serverContent.modelTurn.parts[].inlineData.{mimeType,data}` | flat delta stream ⟷ per-chunk modelTurn Content; group/ungroup + rate tag |
| Output turn completion | `response.audio.done` + `response.done` (`status`) | `serverContent.{turnComplete,generationComplete}` | response.done(completed)⟶turnComplete; Gemini's generationComplete has no OpenAI twin (collapse, warn) |
| Server VAD speech boundary | `input_audio_buffer.speech_started` / `speech_stopped` — `audio_{start,end}_ms`, `item_id` | *(internal; only `interrupted` surfaces)* | DROP toward Gemini (warn) — see `openai_speech_boundary` |
| Tool call (model→host) | `response.function_call_arguments.delta`/`.done` — `call_id`, `name`, `arguments` (JSON **string**, streamed) | `toolCall.functionCalls[].{id,name,args}` (JSON **object**, whole) | **id: `call_id`⟷`id`**; accumulate deltas + `JSON.parse` toward Gemini; stringify + chunk toward OpenAI |
| Tool result (host→model) | `conversation.item.create` function_call_output — `call_id`, `output` (string) | `toolResponse.functionResponses[].{id,name,response}` (object) | `call_id`⟷`id` (same value); parse/stringify; Gemini needs `name` — remember from originating call |
| Barge-in / truncate / cancel | `conversation.item.truncate` (`item_id`,`content_index`,`audio_end_ms`) + `response.cancel` | `serverContent.interrupted=true` | interrupted⟶synthesize response.cancel + best-effort truncate (ms precision lost, warn) — see `openai_truncate_precision` |
| Input transcription | `conversation.item.input_audio_transcription.completed.transcript` (in transcript golden) | `serverContent.inputTranscription.text` | transcript⟷text; enabled via `input_audio_transcription`⟷`inputAudioTranscription` |
| Output transcription | `response.done` assistant `content[].transcript` | `serverContent.outputTranscription.text` | relocate text between content item and standalone message |
| Usage / tokens | `response.done.response.usage.{input,output,total}_tokens` + `*_token_details.{text,audio}` | `usageMetadata.{promptTokenCount,responseTokenCount,totalTokenCount}` + `*TokensDetails[]` | input⟷prompt, output⟷response, total⟷total; modality split object⟷array; attached-to-response ⟷ standalone message |

Correlation-ID note: the **tool call/result** correlation is the load-bearing join across the
whole conversation — OpenAI's `call_id` and Gemini's `functionCalls[].id` / `functionResponses[].id`
must round-trip identically. The `transcript.jsonl` goldens in both dialects carry the same logical
conversation (connect → config → audio turn → tool call → tool result → audio out → barge-in → close)
so the cross-parity leg can diff the bridged stream against the opposite golden.

## Asymmetry table (one-dialect-only concepts)

Each row is a concept that exists in exactly one dialect. `handling` is what the bridge does; the
named fixture exercises it. This is the table the cross-parity verdict checks.

| ID | Only in | Concept | Exercising fixture | Handling |
|---|---|---|---|---|
| `openai_g711` | OpenAI | g711 μ-law/a-law telephony codecs | `openai/session.update.semantic_vad.json` | drop+warn / transcode g711⟷pcm16 |
| `openai_semantic_vad` | OpenAI | `semantic_vad` (eagerness-driven) | `openai/session.update.semantic_vad.json` | drop+warn; map eagerness→nearest sensitivity |
| `openai_truncate_precision` | OpenAI | sample-accurate truncate (`audio_end_ms`) | `openai/conversation.item.truncate.json` | drop+warn; ms precision lost toward Gemini |
| `openai_speech_boundary` | OpenAI | explicit VAD `speech_started`/`speech_stopped` w/ ms | `openai/input_audio_buffer.speech_started.json` | drop+warn; Gemini keeps detection internal |
| `openai_buffer_clear` | OpenAI | `input_audio_buffer.clear` | `openai/input_audio_buffer.clear.json` | drop; no Gemini clear |
| `openai_response_overrides` | OpenAI | per-response config via `response.create.response{}` | `openai/response.create.json` | drop+warn; Gemini has setup-time config only |
| `openai_noise_reduction` | OpenAI | input `noise_reduction` (GA) | `openai/session.update.ga_nested.json` | drop; no equivalent |
| `openai_structured_error` | OpenAI | structured in-band `error` event | `openai/error.json` | drop+warn; Gemini uses WS close codes |
| `openai_event_id` | OpenAI | client-settable `event_id` echoed in errors | `openai/session.update.json` | drop; Gemini has no client correlation id |
| `gemini_setup_complete` | Gemini | `setupComplete` handshake gate | `gemini/setupComplete.json` | synthesize; OpenAI has no gate |
| `gemini_tool_call_cancellation` | Gemini | `toolCallCancellation` (retract pending call) | `gemini/toolCallCancellation.json` | drop+warn; tell host out of band |
| `gemini_generation_complete` | Gemini | `generationComplete` distinct from `turnComplete` | `gemini/serverContent.turnComplete.json` | collapse into `response.done` |
| `gemini_go_away` | Gemini | `goAway` disconnect warning (`timeLeft`) | `gemini/goAway.json` | drop+warn; surface host-side only |
| `gemini_audio_stream_end` | Gemini | `realtimeInput.audioStreamEnd` | `gemini/realtimeInput.audioStreamEnd.json` | map to `input_audio_buffer.commit` (manual VAD) |

## Fixture inventory

- `testing/voice-conformance/fixtures/openai/` — per-event captured-shape JSON for the event
  families above plus `transcript.jsonl` (full session golden).
- `testing/voice-conformance/fixtures/gemini/` — the `BidiGenerateContent` equivalents plus a
  parallel `transcript.jsonl` golden of the same conversation.

Every `.json` fixture validates under `jq .`; every fixture path referenced by
`voice-cross-dialect-map.json` exists.
