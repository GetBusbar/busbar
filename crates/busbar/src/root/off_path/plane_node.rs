// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The node's end post, built once when the node starts.

use std::sync::{Arc, Mutex};

use foldhash::HashMap;

use crate::root::plane_node::{Node, NodeEndPost};

impl NodeEndPost {
    /// The end post over `node`, with its open-unit shards.
    #[must_use]
    pub fn new(node: Arc<Node>) -> Self {
        let open = (0..busbar_kernel::inflight::SHARDS)
            .map(|_| Mutex::new(HashMap::default()))
            .collect();
        NodeEndPost {
            node: Arc::downgrade(&node),
            open,
        }
    }
}
