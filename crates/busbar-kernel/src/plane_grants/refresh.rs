// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`KeyRefresh`]: core's KEYS_STALE refresh policy for one auth instance (IF §12.11).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_loader::ports::auth::AuthPort;
use busbar_plugin_loader::ports::{CallCx, PortError};
use tokio::sync::OnceCell;
use tokio::time::Instant;

/// The least `min_interval` core keeps (config `auth.unknown_key_refresh_s`, min 5 s).
pub(crate) const MIN_INTERVAL: Duration = Duration::from_secs(5);

/// One refresh round: its outcome, set once by whichever caller's run finishes first. A run whose future is
/// dropped leaves the cell empty, so the next caller of the same round runs it instead (no waiter is stranded).
type Round = Arc<OnceCell<Result<(), PortError>>>;

#[derive(Default)]
struct State {
    /// When the current round started (tokio's clock, so a paused test clock drives it).
    last_started: Option<Instant>,
    round: Option<Round>,
}

/// KEYS_STALE handling, owned by the auth adapter (L5) with this core policy: per auth instance, at most one
/// `refresh` in flight (later KEYS_STALE verifies await the same one), and at most one started per
/// `min_interval` (config `auth.unknown_key_refresh_s`, default 30 s, min 5 s). After it completes, the verify
/// runs once more; a second KEYS_STALE or a declined refresh => `Verdict::Rejected { code: BAD_CREDENTIAL }`.
pub struct KeyRefresh {
    min_interval: Duration,
    state: Mutex<State>,
}

impl KeyRefresh {
    /// `min_interval` below `MIN_INTERVAL` is raised to it.
    pub fn new(min_interval: std::time::Duration) -> Self {
        Self {
            min_interval: min_interval.max(MIN_INTERVAL),
            state: Mutex::new(State::default()),
        }
    }

    /// Some(fut) = run or join the single-flight refresh; None = declined by the rate limit.
    pub fn refresh<'a>(
        &'a self,
        port: &'a dyn AuthPort,
        cx: CallCx,
    ) -> Option<BoxFut<'a, Result<(), PortError>>> {
        let round = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            match &state.round {
                Some(round) if !round.initialized() => Arc::clone(round),
                _ => {
                    let now = Instant::now();
                    if state
                        .last_started
                        .is_some_and(|at| now.duration_since(at) < self.min_interval)
                    {
                        return None;
                    }
                    let round: Round = Arc::new(OnceCell::new());
                    state.last_started = Some(now);
                    state.round = Some(Arc::clone(&round));
                    round
                }
            }
        };
        Some(Box::pin(async move {
            round
                .get_or_init(|| async move { port.refresh(cx).await.map(|_| ()) })
                .await
                .clone()
        }))
    }
}
