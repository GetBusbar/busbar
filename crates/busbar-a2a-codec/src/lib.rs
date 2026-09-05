// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A WIRE VOCABULARY — the pure half of the Agent-to-Agent protocol plugin.
//!
//! `busbar-a2a` held two things behind one name: this vocabulary — the JSON canonicalization a card
//! signature is taken over, the anomaly grammar a refusal is spelled in, the meter-class
//! projection, the durable task and task-event record shapes, and the mount paths and registry key
//! the plane is known by — and the
//! A2A plane that carries them over the network (the axum REST and JSON-RPC routes, the tonic gRPC
//! binding, the reqwest relay leg, the push-notification delivery, the mTLS transport). The plane
//! crate `busbar-plane-a2a` adapts the vocabulary and must not link the server: a plane is a PURE
//! kind whose whole transitive closure is scanned, and the server stack put `hyper`, `reqwest`,
//! `axum`, `tonic` and a socket-capable `tokio` in it.
//!
//! So the vocabulary lives here, naming nothing but `busbar-api`'s durable-record contracts and
//! serde. `busbar-a2a` depends on this crate and re-exports every module that moved under its old
//! path, so `busbar_a2a::record::…`, `busbar_a2a::TaskRow` and `crate::a2a::canonical::…` resolve
//! exactly what they always did. The split is a MOVE: no item changed shape crossing it.

/// The modules that moved keep their `a2a::` parent, so their in-crate paths are the ones the plane
/// half still spells (`super::canonical::…`, `crate::a2a::meter::…`) and the move is invisible to
/// every caller.
///
/// WHAT DID NOT MOVE, and why it reads like it should have: `a2a::idmap`, the request-id remapping
/// table, is a lookup THROUGH the task registry (`taskstore::TASKS::get_scoped`) — it refuses to
/// answer for a task the caller does not own — and that registry is a `tokio::sync`-guarded process
/// singleton. The scoping is the point of the module, so the module stays with the store it scopes
/// against rather than being weakened into a pure map to fit here.
pub mod a2a {
    pub mod anomaly;
    pub mod canonical;
    pub mod meter;
}

pub mod record;

/// THE A2A PLANE'S DURABLE RECORD TYPES, re-exported at the crate root exactly as `busbar-a2a`
/// exposes them — so the parent crate's own root re-export is a forward of this one and there is
/// one definition rather than two spellings of it.
pub use record::{TaskEventRow, TaskRow};

/// THE REGISTRY KEY A2A IS KNOWN BY, in the plane registry and in the plugin contract alike.
///
/// Named ONCE, here, on the pure side of the split, because two declarations read it and both must
/// agree: `busbar-a2a`'s `PLANE_DECL.key` and the `busbar-plane-a2a` contract plane's `KEY`. The
/// plane crate is a pure kind and cannot name `busbar-a2a` at all, so a key spelled on the server
/// side would be a key the plane could only copy — which is how two answers to "what is this plane
/// called" start to differ.
pub const PLANE_KEY: &str = "a2a";

/// THE CONFIGURATION SECTION THIS PLANE OWNS, named here for the same reason [`PLANE_KEY`] is: the
/// plane declaration states it and the contract plane's configuration schema is asserted against it,
/// and those two are on opposite sides of the purity seam.
pub const CONFIG_SECTION: &str = "agents";

/// THE PLANE'S MOUNT, the path prefix the A2A plane's HTTP bindings are served under. Every route
/// this plane serves over HTTP is under it, and the host's plane dispatch matches on it at a segment
/// boundary, so `/a2ax` is somebody else's path.
///
/// It sits on the CODEC side of the split because it is a claim about the wire, and the claim is
/// read from BOTH sides: `busbar_a2a::a2a::serve` composes agent endpoints and the protected-resource
/// metadata path from it, and `busbar-plane-a2a` declares its path claims against it. Two spellings
/// of a mount is a plane claiming a path nothing is served at.
pub const MOUNT_PATH: &str = "/a2a";

/// THE PATH PREFIX THE gRPC BINDING IS SERVED AT, and busbar did not choose it.
///
/// gRPC derives a request path from the `.proto`'s package and service name — `lf.a2a.v1` and
/// `A2AService` in the a2aproject's own canonical `a2a.proto`, vendored by `a2a-pb` — and a client
/// is given an AUTHORITY, never a path prefix, so there is no spelling of this that could live under
/// [`MOUNT_PATH`]. Written as a constant beside the mount it is not under, because "the A2A plane
/// answers here too" is a fact the mount table has to be told or this binding's tokens go unchecked
/// for audience.
pub const GRPC_MOUNT_PATH: &str = "/lf.a2a.v1.A2AService";
