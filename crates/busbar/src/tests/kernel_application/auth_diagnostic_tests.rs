// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::auth::AuthMiddleware;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn capture<T>(f: impl FnOnce() -> T) -> (T, Buf) {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let out = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        f()
    });
    (out, buf)
}

#[test]
fn auth_chain_open_relay_diag_fires_on_empty_data_plane_chain() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let cfg = busbar_kernel::config::AuthCfg::default_none();
    let (chain, buf) = capture(|| {
        AuthMiddleware::new(
            &cfg,
            &registry,
            &busbar_kernel::config::secret::SecretResolver::builtins_only(),
        )
        .expect("the actual root constructs the empty chain")
    });
    assert!(
        chain.is_open(),
        "an empty chain with no keys verifier is open"
    );
    let text = buf.text();
    assert!(
        text.contains("diag=BUSBAR-4004"),
        "expected AUTH_CHAIN_OPEN_RELAY (BUSBAR-4004) to fire; got: {text:?}"
    );
    assert!(
        text.contains("auth.chain is empty (open relay)"),
        "message text must match the v1.5.5 wording; got: {text:?}"
    );
}
