// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! S0 owns the I/O executor independently of workers that perform synchronous configuration reads.

pub(crate) struct ProcessIo {
    handle: tokio::runtime::Handle,
    // Teardown consumes the already-created sender and thread; neither is late wiring.
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ProcessIo {
    pub(crate) fn new() -> Result<Self, String> {
        let runtime = busbar_kernel::rt::current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("busbar-conn-io".into())
            .spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
                runtime.shutdown_background();
            })
            .map_err(|error| error.to_string())?;
        Ok(Self {
            handle,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    pub(crate) fn handle(&self) -> tokio::runtime::Handle {
        self.handle.clone()
    }
}

impl Drop for ProcessIo {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
