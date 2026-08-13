// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A gRPC BINDING: the a2aproject's own service, implemented over BUSBAR'S admission and
//! BUSBAR'S store.
//!
//! ## WHAT IS TAKEN FROM THE SDK, AND THE ONE THING THAT IS NOT
//!
//! Everything protocol-shaped here is generated from the a2aproject's canonical `a2a.proto`, which
//! `a2a-pb` vendors: the message types, the service descriptor, the path
//! `/lf.a2a.v1.A2AService/*` a client dials, the ProtoJSON mapping each message has. Nothing in this
//! file hand-writes a wire fact.
//!
//! What is NOT taken is `a2a-grpc`, and it is the crate that looks exactly like the one for this
//! job. Its `GrpcHandler` implements this same generated service *by wrapping
//! `a2a_server::RequestHandler`*, so adopting it pulls `a2a-server-lf`'s `AgentExecutor`, `TaskStore`
//! and `DefaultRequestHandler` — a second execution model beside the durable one busbar's plugin ABI
//! and per-principal audit chain are built on. **Two task stores means two answers to "what
//! happened", and the one a customer's auditor reads is whichever was wired last.** So busbar
//! implements the trait itself, which is this file, and the implementation is thin because the
//! answer already exists: [`super::receive::invoke`].
//!
//! ## THE BINDING IS FRAMING, NOT A SECOND IMPLEMENTATION
//!
//! ```text
//! codec   = matrix[protocol][operation]   // unchanged — the codec never learns the transport
//! framing = transport.frame(codec)        // Transport::Grpc, and this module is its A2A arm
//! ```
//!
//! A2A's gRPC binding is the SAME protocol as its JSON-RPC binding: the TCK's own tables give one
//! name to both (`SendMessage` is the gRPC rpc AND the v1.0 JSON-RPC method), and A2A v1.0's JSON
//! representation of a request message IS that message's ProtoJSON. So every RPC below does three
//! things and no more:
//!
//! 1. transcode the protobuf request to its canonical JSON through the SDK's own conversions,
//! 2. hand it to [`super::receive::invoke`] — the SAME admission, catalogue, dispatch, meter, audit,
//!    task store and relay the JSON-RPC leg goes through, with nothing skipped and nothing added,
//! 3. transcode the answer back, or turn the JSON-RPC error into the `grpc-status` A2A section 5.4
//!    binds it to ([`super::rpcerror::A2aError::grpc_status`]).
//!
//! There is no second admission path, no second store and no second relay. A defect fixed on one
//! binding is fixed on the other because there is only one of it.
//!
//! ## THE TYPED PARSE, AND WHY THIS BINDING CANNOT BE A COURIER
//!
//! Everywhere else on this plane busbar forwards the caller's BYTES unmodified, so a member the
//! modelled types do not know still reaches the backend. That is not available here: the caller
//! spoke protobuf and the backend speaks JSON, so *somebody* must author the translation, and the
//! honest thing is to say so rather than to pretend otherwise. The translation is the SDK's — `a2a`
//! (the `a2a-lf` crate; its lib name is `a2a`, not `a2a_lf`) is the typed model and
//! `a2a_pb::protojson_conv` is the ProtoJSON mapping — and it exists EXACTLY ONCE per direction, so
//! there is one reader and one writer and nothing to diverge. What a proto field the SDK's own
//! conversions do not carry costs is a field dropped on this binding and only this one; the
//! JSON-RPC binding's verbatim property is untouched.
//!
//! ## HOW A tonic SERVICE SATISFIES `CoreRouteTable`
//!
//! busbar mounts core routes exclusively through [`crate::core_routes::CoreRouter`] so every route
//! declares its admission bar in the same act that wires it, and a pre-built router entering the
//! tree with no `CoreRouteTable` entry is the one state that table exists to make impossible. A
//! tonic service is a `tower::Service`, not an `axum::Router`, so `Router::route_service` would be
//! the obvious mount — and it is exactly the pre-built-router shape the rule refuses.
//!
//! So the service is not mounted at all. [`serve`] is an ORDINARY AXUM HANDLER, wired by
//! `CoreRouter::route(GRPC_ROUTE_PATH, Post, RouteAuth::Key, serve)` like every other core route,
//! and the generated `A2aServiceServer` is CONSTRUCTED INSIDE IT, per request, around a `Busbar`
//! that already holds this request's authenticated principal and governance context. Three things
//! fall out, and each is why this is the right shape rather than a workaround:
//!
//! * the route has a `CoreRouteTable` entry, declared in the act that mounts it, like every other;
//! * the service reads its identity from ordinary Rust state rather than fishing extensions out of
//!   a request, so there is no way to construct one that has not been through the auth middleware;
//! * `PlaneDispatch` claims `/lf.a2a.v1.A2AService` for [`crate::plane::Plane::A2a`], so the RFC
//!   8707 audience check that guards `/a2a` guards this path too. That is not tidiness: the audience
//!   is resolved THROUGH the mount table, so an unclaimed path is one where no token's `aud` is
//!   checked, and this binding would have admitted a token minted for any other resource.
//!
//! ## CLEARTEXT HTTP/2 IS ALREADY SERVED, AND THAT IS WHY THERE IS NO SECOND LISTENER
//!
//! gRPC needs HTTP/2. `axum::serve` drives `hyper_util`'s `auto::Builder`, whose `server-auto`
//! feature requires `hyper/http2`, and busbar's graph already enables it (tonic and reqwest both ask
//! for it) — so busbar's existing listener already accepts h2c prior-knowledge connections. The gRPC
//! binding therefore rides the port, the TLS termination, the auth middleware and the plane
//! observability busbar already has, instead of a second socket with a second set of answers to
//! every operational question.

use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tonic::{Request, Status};

use a2a_pb::proto::a2a_service_server::{A2aService, A2aServiceServer};
use a2a_pb::{pbconv, proto, protojson_conv};

/// THE AXUM ROUTE PATTERN the gRPC binding is mounted at.
///
/// `{method}` is the RPC name; the generated service matches the full path itself and answers
/// `UNIMPLEMENTED` for one it does not know, so the pattern claims the service's whole namespace and
/// nothing outside it. Derived from [`super::serve::GRPC_MOUNT_PATH`], which is the same string
/// `PlaneDispatch` claims, so the path the router serves and the path the audience check guards
/// cannot drift apart.
pub(crate) fn route_path() -> String {
    format!("{}/{{method}}", super::serve::GRPC_MOUNT_PATH)
}

/// The A2A protocol version this binding speaks. The gRPC service descriptor IS the v1 protocol —
/// there is no v0.3 protobuf — so a request that names no version is a 1.0 request, unlike the HTTP
/// bindings where an absent header means 0.3.
const GRPC_A2A_VERSION: &str = "1.0";

/// The `A2A-Version` metadata key, lower-cased as HTTP/2 requires every header name to be.
const A2A_VERSION_METADATA: &str = "a2a-version";

/// THE HANDLER, and the whole of this binding's mount. See the module note for why the tonic service
/// is built here rather than mounted as a router.
///
/// The three extractors are the same three `super::receive::plane_rpc` takes, in the same order, and
/// they are what makes the constructed service busbar's rather than the SDK's: `gov` carries the key
/// every meter and audit record is written against, and `principal` is who the auth middleware said
/// is calling. Neither is reachable from inside a `tower::Service` mounted as a router, which is the
/// other reason this shape is the right one.
pub(crate) async fn serve(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(principal): axum::extract::Extension<crate::auth::AuthPrincipal>,
    req: axum::extract::Request,
) -> Response {
    // THE LEG, NAMED, and named off the axis rather than off a literal. `Transport::name` is
    // documented as "the label that says WHICH LEG a request arrived on, which is what makes a
    // per-transport conformance number readable from busbar's own telemetry once a second transport
    // arms" — this is that second transport, and this is the only place on it that knows.
    tracing::debug!(
        transport = crate::transport::Transport::Grpc.name(),
        rpc = req.uri().path(),
        "a2a: a request arrived on the gRPC binding"
    );
    let mut service = A2aServiceServer::new(Busbar {
        app,
        gov,
        principal,
    });
    match tower::Service::call(&mut service, req).await {
        Ok(resp) => resp.map(axum::body::Body::new).into_response(),
        // `A2aServiceServer`'s error type is `Infallible`, so this arm cannot run. Written rather
        // than unwrapped because an `unwrap` on a routing hot path is a panic waiting for the day
        // the generated code's error type changes.
        Err(_) => Status::internal("the gRPC service did not answer")
            .into_http::<tonic::body::Body>()
            .map(axum::body::Body::new)
            .into_response(),
    }
}

/// ONE REQUEST'S WORTH OF BUSBAR, handed to the generated service.
///
/// Built per request and dropped with it. That is deliberate and is not a cost: the three fields are
/// an `Arc` clone and two small owned values, and holding the principal IN the service is what makes
/// "this call was admitted" a fact the type carries rather than one a handler has to re-derive.
struct Busbar {
    app: Arc<crate::state::App>,
    gov: crate::governance::GovCtx,
    principal: crate::auth::AuthPrincipal,
}

impl Busbar {
    /// THE ONE CALL. Frame the RPC as the v1.0 JSON-RPC request it is, run it through the plane's
    /// single ingress, and hand back the `result` member — or the `error` member, mapped to the
    /// gRPC status A2A section 5.4 binds it to.
    ///
    /// `id` is busbar's, not the caller's: gRPC has no correlation id member, so there is nothing to
    /// echo. It is a fixed literal rather than a generated one because it never leaves this
    /// function — the ingress answers under it and this function reads the answer back immediately.
    async fn call(&self, method: &str, params: Value, version: String) -> Result<Value, Status> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let wire = super::receive::Wire::for_grpc(version);
        let response = super::receive::invoke(
            Arc::clone(&self.app),
            self.gov.clone(),
            self.principal.clone(),
            super::receive::Target::FromCatalogue,
            wire,
            // THE LEG, CARRIED RATHER THAN COMPARED. The ingress reads it in exactly one place —
            // the metric label it emits for every A2A request — and this is the only site that
            // knows a gRPC frame arrived, because everything below it has already been re-framed
            // as the JSON-RPC envelope above.
            crate::transport::Transport::Grpc,
            axum::body::Bytes::from(body.to_string().into_bytes()),
        )
        .await;
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, MAX_ANSWER_BYTES)
            .await
            .map_err(|_| Status::internal("the answer could not be read"))?;
        // A REFUSAL THAT NEVER REACHED THE JSON-RPC LAYER still has to become a gRPC status. The
        // ingress answers every A2A-shaped refusal in the plane's own envelope, so the common path
        // is the parse below; a body that is not one of those is an HTTP-layer answer and takes the
        // status gRPC's own HTTP mapping would give it.
        let Ok(envelope) = serde_json::from_slice::<Value>(&bytes) else {
            return Err(status_for_http(parts.status));
        };
        if let Some(error) = envelope.get("error") {
            return Err(status_for_error(error, parts.status));
        }
        envelope
            .get("result")
            .cloned()
            .ok_or_else(|| status_for_http(parts.status))
    }
}

/// The ceiling on a single buffered answer read back out of the ingress. Generous, because the
/// ingress has already applied busbar's own body limits on the way in and a task's artifacts are the
/// legitimate reason an answer is large; bounded, because `to_bytes` with no limit is an unbounded
/// allocation driven by a backend busbar does not control.
const MAX_ANSWER_BYTES: usize = 64 * 1024 * 1024;

/// THE gRPC STATUS FOR A JSON-RPC ERROR OBJECT, read off the code rather than the message.
///
/// The code is the protocol fact and maps through the one section 5.4 table
/// ([`super::rpcerror::A2aError::grpc_status`]). A code that table does not define — a backend's
/// own extension, relayed — falls back to the HTTP status, which is the answer gRPC's own
/// HTTP-to-status mapping would have produced anyway.
fn status_for_error(error: &Value, http: axum::http::StatusCode) -> Status {
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("the request was refused")
        .to_string();
    match error
        .get("code")
        .and_then(Value::as_i64)
        .and_then(super::rpcerror::A2aError::from_code)
    {
        Some(a2a) => Status::new(a2a.grpc_status(), message),
        None => Status::new(status_for_http(http).code(), message),
    }
}

/// The gRPC status an HTTP status means, as the gRPC specification's own HTTP-to-status table
/// defines it. Written here rather than left to the client because busbar is answering INSIDE a
/// gRPC call at this point: a client only applies that table to a response that carries no
/// `grpc-status` at all, and one that carries the wrong one is worse than one that carries none.
fn status_for_http(status: axum::http::StatusCode) -> Status {
    use axum::http::StatusCode;
    let code = match status {
        StatusCode::BAD_REQUEST => tonic::Code::Internal,
        StatusCode::UNAUTHORIZED => tonic::Code::Unauthenticated,
        StatusCode::FORBIDDEN => tonic::Code::PermissionDenied,
        StatusCode::NOT_FOUND => tonic::Code::Unimplemented,
        StatusCode::TOO_MANY_REQUESTS
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::GATEWAY_TIMEOUT => tonic::Code::Unavailable,
        StatusCode::PAYLOAD_TOO_LARGE => tonic::Code::ResourceExhausted,
        _ => tonic::Code::Unknown,
    };
    Status::new(code, format!("busbar answered HTTP {}", status.as_u16()))
}

/// The `A2A-Version` a caller asked for, read off gRPC metadata, or [`GRPC_A2A_VERSION`] when it
/// sent none. Absent means 1.0 here and 0.3 on the HTTP bindings, and that is not an inconsistency:
/// the version an omission means is a property of the BINDING, and this binding's service descriptor
/// is the v1 protocol.
fn requested_version<T>(req: &Request<T>) -> String {
    req.metadata()
        .get(A2A_VERSION_METADATA)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| GRPC_A2A_VERSION.to_string())
}

/// PROTOBUF IN → CANONICAL JSON, through the SDK's own conversions and nothing else.
///
/// `pbconv` maps the generated protobuf type onto `a2a`'s typed model and `protojson_conv` maps that
/// model onto ProtoJSON — which is what A2A v1.0's JSON representation of the message IS. Both are
/// `a2a-pb`'s. The alternative (hand-writing the field names) is precisely the hand-rolling this
/// adoption exists to end.
fn to_params<N: protojson_conv::ProtoJsonPayload>(native: &N) -> Result<Value, Status> {
    protojson_conv::to_value(native)
        .map_err(|e| Status::invalid_argument(format!("the request could not be read: {e}")))
}

/// CANONICAL JSON → PROTOBUF, the same mapping in the other direction.
fn from_result<N: protojson_conv::ProtoJsonPayload>(result: Value) -> Result<N, Status> {
    protojson_conv::from_value(result)
        .map_err(|e| Status::internal(format!("the answer could not be rendered: {e}")))
}

/// THE MEMBERS OF BUSBAR'S OWN AGENT CARD THAT THE NORMATIVE `a2a.proto` DOES NOT MODEL, as
/// `(object path, member)` pairs.
///
/// One entry today: `capabilities.stateTransitionHistory`. It is an A2A v0.3 member, it is declared
/// by the specification's own sample card in section 8.5, and `a2a.proto`'s `AgentCapabilities` —
/// which SPEC 1.4 makes the normative definition — has no such field. The generated ProtoJSON type
/// is `deny_unknown_fields`, so the transcode below did not drop it: it FAILED, and this rpc
/// answered `Internal` with a serde message for every caller. A mounted path that answers nothing is
/// not an implemented method, and it was invisible to the official suite because `CARD-EXT-002`
/// skips itself the moment a card is configured.
const UNMODELLED_CARD_MEMBERS: &[(&str, &str)] = &[("capabilities", "stateTransitionHistory")];

/// BUSBAR'S CARD, NARROWED TO WHAT A PROTOBUF `AgentCard` CAN CARRY — and NOT reshaped.
///
/// This is deliberately not the thing `testing/a2a-tck/WAIVERS.md` refuses to do. That decision,
/// dated and recorded, is that **busbar does not change the card it PUBLISHES** to satisfy a
/// generated schema the specification's own sample card contradicts; the document every A2A client
/// reads over the two HTTP bindings is untouched by this function and keeps every member it has.
///
/// What is decided here is different and is not a choice at all: this binding's answer IS a
/// protobuf `AgentCard`, and a member the message has no field for cannot be put on this wire in any
/// shape. The only two available answers are "the card, minus what protobuf cannot represent" and
/// "no card". Dropping the member costs a gRPC caller that member; failing the transcode costs it
/// the whole card — and the module note above already states the rule this follows: *what a proto
/// field the SDK's own conversions do not carry costs a field dropped on this binding and only this
/// one*.
///
/// LISTED, never guessed, and never a blanket "ignore what does not parse". A generic leniency here
/// would silently swallow the next real divergence between busbar's card and the specification's
/// message; a named list makes each drop a line somebody wrote down, with the reason attached.
fn narrowed_to_the_proto(mut card: Value) -> Value {
    let Some(root) = card.as_object_mut() else {
        return card;
    };
    for (parent, member) in UNMODELLED_CARD_MEMBERS {
        if let Some(obj) = root.get_mut(*parent).and_then(Value::as_object_mut) {
            obj.remove(*member);
        }
    }
    card
}

/// The stream a server-streaming RPC answers with. Boxed because both streaming RPCs produce it
/// from the same function and a named opaque type per RPC would be two names for one thing.
type EventStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<proto::StreamResponse, Status>> + Send>>;

#[tonic::async_trait]
impl A2aService for Busbar {
    async fn send_message(
        &self,
        request: Request<proto::SendMessageRequest>,
    ) -> Result<tonic::Response<proto::SendMessageResponse>, Status> {
        let version = requested_version(&request);
        let native = pbconv::from_proto_send_message_request(request.get_ref());
        let result = self
            .call("SendMessage", to_params(&native)?, version)
            .await?;
        let answer: a2a::SendMessageResponse = from_result(result)?;
        Ok(tonic::Response::new(
            pbconv::to_proto_send_message_response(&answer),
        ))
    }

    type SendStreamingMessageStream = EventStream;

    async fn send_streaming_message(
        &self,
        request: Request<proto::SendMessageRequest>,
    ) -> Result<tonic::Response<Self::SendStreamingMessageStream>, Status> {
        let version = requested_version(&request);
        let native = pbconv::from_proto_send_message_request(request.get_ref());
        self.stream("SendStreamingMessage", to_params(&native)?, version)
            .await
    }

    async fn get_task(
        &self,
        request: Request<proto::GetTaskRequest>,
    ) -> Result<tonic::Response<proto::Task>, Status> {
        let version = requested_version(&request);
        let native = pbconv::from_proto_get_task_request(request.get_ref());
        let result = self.call("GetTask", to_params(&native)?, version).await?;
        let task: a2a::Task = from_result(result)?;
        Ok(tonic::Response::new(pbconv::to_proto_task(&task)))
    }

    async fn list_tasks(
        &self,
        request: Request<proto::ListTasksRequest>,
    ) -> Result<tonic::Response<proto::ListTasksResponse>, Status> {
        let version = requested_version(&request);
        let native = pbconv::from_proto_list_tasks_request(request.get_ref());
        let result = self.call("ListTasks", to_params(&native)?, version).await?;
        let answer: a2a::ListTasksResponse = from_result(result)?;
        Ok(tonic::Response::new(pbconv::to_proto_list_tasks_response(
            &answer,
        )))
    }

    async fn cancel_task(
        &self,
        request: Request<proto::CancelTaskRequest>,
    ) -> Result<tonic::Response<proto::Task>, Status> {
        let version = requested_version(&request);
        let native = pbconv::from_proto_cancel_task_request(request.get_ref());
        let result = self
            .call("CancelTask", to_params(&native)?, version)
            .await?;
        let task: a2a::Task = from_result(result)?;
        Ok(tonic::Response::new(pbconv::to_proto_task(&task)))
    }

    type SubscribeToTaskStream = EventStream;

    async fn subscribe_to_task(
        &self,
        request: Request<proto::SubscribeToTaskRequest>,
    ) -> Result<tonic::Response<Self::SubscribeToTaskStream>, Status> {
        let version = requested_version(&request);
        let native = pbconv::from_proto_subscribe_to_task_request(request.get_ref());
        self.stream("SubscribeToTask", to_params(&native)?, version)
            .await
    }

    async fn create_task_push_notification_config(
        &self,
        request: Request<proto::TaskPushNotificationConfig>,
    ) -> Result<tonic::Response<proto::TaskPushNotificationConfig>, Status> {
        let version = requested_version(&request);
        let native = pbconv::from_proto_task_push_notification_config(request.get_ref());
        let result = self
            .call(
                "CreateTaskPushNotificationConfig",
                to_params(&native)?,
                version,
            )
            .await?;
        let answer: a2a::TaskPushNotificationConfig = from_result(result)?;
        Ok(tonic::Response::new(
            pbconv::to_proto_task_push_notification_config(&answer),
        ))
    }

    async fn get_task_push_notification_config(
        &self,
        request: Request<proto::GetTaskPushNotificationConfigRequest>,
    ) -> Result<tonic::Response<proto::TaskPushNotificationConfig>, Status> {
        let version = requested_version(&request);
        let native =
            pbconv::from_proto_get_task_push_notification_config_request(request.get_ref());
        let result = self
            .call(
                "GetTaskPushNotificationConfig",
                to_params(&native)?,
                version,
            )
            .await?;
        let answer: a2a::TaskPushNotificationConfig = from_result(result)?;
        Ok(tonic::Response::new(
            pbconv::to_proto_task_push_notification_config(&answer),
        ))
    }

    async fn list_task_push_notification_configs(
        &self,
        request: Request<proto::ListTaskPushNotificationConfigsRequest>,
    ) -> Result<tonic::Response<proto::ListTaskPushNotificationConfigsResponse>, Status> {
        let version = requested_version(&request);
        let native =
            pbconv::from_proto_list_task_push_notification_configs_request(request.get_ref());
        let result = self
            .call(
                "ListTaskPushNotificationConfigs",
                to_params(&native)?,
                version,
            )
            .await?;
        let answer: a2a::ListTaskPushNotificationConfigsResponse = from_result(result)?;
        Ok(tonic::Response::new(
            pbconv::to_proto_list_task_push_notification_configs_response(&answer),
        ))
    }

    async fn get_extended_agent_card(
        &self,
        request: Request<proto::GetExtendedAgentCardRequest>,
    ) -> Result<tonic::Response<proto::AgentCard>, Status> {
        let version = requested_version(&request);
        let native = pbconv::from_proto_get_extended_agent_card_request(request.get_ref());
        let result = self
            .call("GetExtendedAgentCard", to_params(&native)?, version)
            .await?;
        let card: a2a::AgentCard = from_result(narrowed_to_the_proto(result))?;
        Ok(tonic::Response::new(pbconv::to_proto_agent_card(&card)))
    }

    async fn delete_task_push_notification_config(
        &self,
        request: Request<proto::DeleteTaskPushNotificationConfigRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        let version = requested_version(&request);
        let native =
            pbconv::from_proto_delete_task_push_notification_config_request(request.get_ref());
        self.call(
            "DeleteTaskPushNotificationConfig",
            to_params(&native)?,
            version,
        )
        .await?;
        // `google.protobuf.Empty` on the wire. The JSON-RPC answer to this verb carries `null`, and
        // there is nothing in either to transcode.
        Ok(tonic::Response::new(()))
    }
}

impl Busbar {
    /// A SERVER-STREAMING RPC, over the ingress's SSE answer.
    ///
    /// The two streaming verbs differ only in their name and params, so the machinery is written
    /// once. What it does is the mirror of [`Self::call`]: run the same ingress, then read the
    /// answer's SHAPE rather than assume it, because the ingress legitimately answers a streaming
    /// request two ways.
    ///
    /// * An SSE body is the streaming answer. Each frame is one JSON-RPC response carrying one
    ///   `StreamResponse`; the frames are re-emitted AS THEY ARRIVE, never buffered. Buffering would
    ///   be simpler and would be wrong: a subscribe to a long-running task produces its first event
    ///   long before its last, and a client that saw nothing until the stream closed would time out
    ///   on a task busbar was serving correctly.
    /// * A JSON body is the ingress's documented unary answer to a streaming request — the backend
    ///   completed the work in one step, which is legal — and becomes a one-event stream, because a
    ///   gRPC server-streaming RPC has no other shape to answer in.
    async fn stream(
        &self,
        method: &str,
        params: Value,
        version: String,
    ) -> Result<tonic::Response<EventStream>, Status> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let wire = super::receive::Wire::for_grpc(version);
        let response = super::receive::invoke(
            Arc::clone(&self.app),
            self.gov.clone(),
            self.principal.clone(),
            super::receive::Target::FromCatalogue,
            wire,
            // THE LEG, CARRIED RATHER THAN COMPARED. The ingress reads it in exactly one place —
            // the metric label it emits for every A2A request — and this is the only site that
            // knows a gRPC frame arrived, because everything below it has already been re-framed
            // as the JSON-RPC envelope above.
            crate::transport::Transport::Grpc,
            axum::body::Bytes::from(body.to_string().into_bytes()),
        )
        .await;
        let (parts, body) = response.into_parts();
        let is_sse = parts
            .headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("text/event-stream"));

        if !is_sse {
            let bytes = axum::body::to_bytes(body, MAX_ANSWER_BYTES)
                .await
                .map_err(|_| Status::internal("the answer could not be read"))?;
            let Ok(envelope) = serde_json::from_slice::<Value>(&bytes) else {
                return Err(status_for_http(parts.status));
            };
            if let Some(error) = envelope.get("error") {
                return Err(status_for_error(error, parts.status));
            }
            let result = envelope
                .get("result")
                .cloned()
                .ok_or_else(|| status_for_http(parts.status))?;
            let event: a2a::StreamResponse = from_result(result)?;
            let one = pbconv::to_proto_stream_response(&event);
            return Ok(tonic::Response::new(Box::pin(futures::stream::once(
                async move { Ok(one) },
            ))));
        }

        Ok(tonic::Response::new(Box::pin(sse_events(body))))
    }
}

/// RE-FRAME AN SSE BODY AS A STREAM OF `StreamResponse` MESSAGES.
///
/// The SSE reader is [`super::relay::sse_data`] — the plane's own, reused rather than copied,
/// because a second reading of "what is the data of this frame" is a second thing to get wrong about
/// continuation lines.
///
/// A frame that carries no JSON-RPC `result` is SKIPPED rather than turned into an error: an SSE
/// stream legitimately carries comments and keep-alives, and the relay passes a backend's own
/// unparseable frames through untouched by design. A frame carrying an `error` ENDS the stream with
/// that error, which is what a JSON-RPC error inside a stream means.
fn sse_events(
    body: axum::body::Body,
) -> impl futures::Stream<Item = Result<proto::StreamResponse, Status>> + Send {
    use futures::StreamExt;
    let frames = futures::stream::unfold(
        (http_body_util::BodyStream::new(body), Vec::<u8>::new()),
        |(mut stream, mut buffered)| async move {
            loop {
                if let Some(frame) = take_frame(&mut buffered) {
                    return Some((Ok::<_, Status>(frame), (stream, buffered)));
                }
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        if let Ok(data) = chunk.into_data() {
                            buffered.extend_from_slice(&data);
                        }
                    }
                    // The stream ended. A trailing partial frame with no blank line after it is
                    // still a frame — a backend that closed the connection cleanly after its last
                    // event should not lose that event.
                    Some(Err(_)) | None => {
                        if buffered.is_empty() {
                            return None;
                        }
                        let rest = std::mem::take(&mut buffered);
                        return Some((
                            Ok(String::from_utf8_lossy(&rest).into_owned()),
                            (stream, buffered),
                        ));
                    }
                }
            }
        },
    );
    frames.filter_map(|frame| async move {
        let frame = match frame {
            Ok(f) => f,
            Err(status) => return Some(Err(status)),
        };
        let data = super::relay::sse_data(&frame)?;
        let envelope: Value = serde_json::from_str(&data).ok()?;
        if let Some(error) = envelope.get("error") {
            return Some(Err(status_for_error(
                error,
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            )));
        }
        let result = envelope.get("result")?.clone();
        Some(
            from_result::<a2a::StreamResponse>(result)
                .map(|e| pbconv::to_proto_stream_response(&e)),
        )
    })
}

/// The next complete SSE frame in `buffered`, consumed from it, or `None` when there is not one yet.
/// A frame ends at a blank line, in any of the three line-ending spellings the SSE grammar allows.
fn take_frame(buffered: &mut Vec<u8>) -> Option<String> {
    const TERMINATORS: [&[u8]; 3] = [b"\r\n\r\n", b"\n\n", b"\r\r"];
    let (at, len) = TERMINATORS
        .iter()
        .filter_map(|t| find(buffered, t).map(|pos| (pos, t.len())))
        .min_by_key(|(pos, len)| (*pos, std::cmp::Reverse(*len)))?;
    let rest = buffered.split_off(at + len);
    let frame = std::mem::replace(buffered, rest);
    Some(String::from_utf8_lossy(&frame[..at]).into_owned())
}

/// The first index of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
#[path = "tests/grpc_tests.rs"]
mod grpc_tests;
