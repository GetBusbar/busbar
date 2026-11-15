// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR'S ONE SANCTIONED COLD MODULE (busbar-bad-patterns BP17): the cold code the
//! request-path tree (`conns`) needs (refusal and diagnostic text), outside the request-path marker,
//! called out of line. Every fn here is `#[cold]` or `#[inline(never)]`, holds no while/loop, and
//! never sweeps request data. One submodule per owning area, named for the module it serves.

pub(crate) mod compose;
pub(crate) mod conns;
pub(crate) mod datagram;
pub(crate) mod dialled;
pub(crate) mod dtls;
pub(crate) mod egress;
pub(crate) mod framing;
pub(crate) mod guard;
pub(crate) mod hostio;
pub(crate) mod lines;
pub(crate) mod process;
pub(crate) mod program;
pub(crate) mod proxy;
pub(crate) mod seal;
pub(crate) mod tls;
