// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT DIRECTION'S WIRE DIALECT: what busbar sends an upstream MCP server and how it reads
//! the answer. Pure builders and readers over values; nothing here opens a connection, holds a
//! session or reads a clock. The engine that drives them hands every fact in as an argument.

pub mod jsonrpc;
