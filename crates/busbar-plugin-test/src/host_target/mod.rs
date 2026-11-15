// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST TARGET (SDK-SAFE-TEST-HOST §10): declared only, so the red tests compile. The fix
//! commit builds it.
#![forbid(unsafe_code)]

#[cfg(feature = "target-http")]
pub mod carrier;

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_plugin_loader::dispatch::Kind;
use busbar_plugin_loader::test_host::{Host, Image, Openable, Opened, Refused as HostRefused};

/// What the verdict names as the subject.
pub const SUBJECT: &str = "host target; kernel not present";

/// Which images a run serves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Images {
    /// The linked door and the cdylib.
    #[default]
    Both,
    /// The cdylib only.
    Cdylib,
    /// The linked door only.
    Linked,
}

impl Images {
    /// The image names this choice serves.
    #[must_use]
    pub fn names(self) -> &'static [&'static str] {
        todo!("T1a")
    }
}

/// `image` of this plugin.
#[must_use]
pub fn image<K: Kind>(_image: &str, _lib_name: &str, _door: DoorFn) -> Image<K> {
    todo!("T1a")
}

/// The host every target image is opened on.
#[must_use]
pub fn host() -> Host {
    todo!("T1a")
}

/// Why a target refused to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// An image did not load, open or ready.
    Image(&'static str, HostRefused),
    /// Not a loopback IP address.
    NotLoopback(String),
    /// A listener or a thread could not start.
    Bind(String),
    /// The command line is wrong.
    Args(String),
}

/// A caller the driver supplies.
pub struct Caller;

impl Caller {
    /// A caller named `name`.
    #[must_use]
    pub fn new(_name: &str) -> Self {
        todo!("T1a")
    }

    /// The bearer token.
    #[must_use]
    pub fn token(self, _bytes: &[u8]) -> Self {
        todo!("T1a")
    }

    /// The entries granted.
    #[must_use]
    pub fn entries(self, _entries: &[&str]) -> Self {
        todo!("T1a")
    }

    /// The caller's name.
    #[must_use]
    pub fn name(&self) -> &str {
        todo!("T1a")
    }

    /// Whether this caller is granted `entry`.
    #[must_use]
    pub fn grants(&self, _entry: &str) -> bool {
        todo!("T1a")
    }
}

/// The driver's callers.
pub struct Callers;

impl Callers {
    /// The caller presenting `token`.
    #[must_use]
    pub fn find(&self, _token: &[u8]) -> Option<Arc<Caller>> {
        todo!("T1a")
    }
}

/// The run report.
#[derive(Clone)]
pub struct Report;

impl Report {
    /// Everything the run was asked and did not serve.
    #[must_use]
    pub fn unserved(&self) -> Vec<String> {
        todo!("T1a")
    }
}

/// The run failed: what it was asked and did not serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unserved(pub Vec<String>);

/// What a target serves on its listeners.
pub trait Subject: Send + 'static {
    /// Binds `image`'s listeners.
    ///
    /// # Errors
    /// When it cannot start.
    fn bind(&mut self, image: &'static str, at: &Binding<'_>) -> Result<Listening, Refused>;
}

/// What a subject binds with.
pub struct Binding<'a>(PhantomData<&'a ()>);

impl Binding<'_> {
    /// The address for the next listener.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        todo!("T1a")
    }

    /// The driver's callers.
    #[must_use]
    pub fn callers(&self) -> &Arc<Callers> {
        todo!("T1a")
    }

    /// The run report.
    #[must_use]
    pub fn report(&self) -> &Report {
        todo!("T1a")
    }
}

/// One image's listeners.
pub struct Listening {
    /// The data listener.
    pub addr: SocketAddr,
    /// The admin listener.
    pub admin: Option<SocketAddr>,
    /// Stops them.
    pub stop: Box<dyn FnOnce() + Send>,
}

/// A host target over `subject`.
pub struct Target<S>(S);

impl<S: Subject> Target<S> {
    /// A target serving `subject`.
    #[must_use]
    pub fn new(subject: S) -> Self {
        Self(subject)
    }

    /// Which images to serve.
    #[must_use]
    pub fn images(self, _images: Images) -> Self {
        todo!("T1a")
    }

    /// Where to listen.
    #[must_use]
    pub fn listen(self, _addr: &str) -> Self {
        todo!("T1a")
    }

    /// The run's seed.
    #[must_use]
    pub fn seed(self, _seed: u64) -> Self {
        todo!("T1a")
    }

    /// A caller the driver supplies.
    #[must_use]
    pub fn caller(self, _caller: Caller) -> Self {
        todo!("T1a")
    }

    /// Maps `entry` to a loopback address.
    #[must_use]
    pub fn upstream(self, _entry: &str, _addr: SocketAddr) -> Self {
        todo!("T1a")
    }

    /// Serves in-process.
    ///
    /// # Errors
    /// Never yet.
    pub fn serve(self) -> Result<Served, Refused> {
        todo!("T1a")
    }

    /// The target as its own process.
    #[must_use]
    pub fn main(self) -> ExitCode {
        todo!("T1a")
    }
}

/// A target serving in-process.
pub struct Served;

impl Served {
    /// `image`'s data listener.
    #[must_use]
    pub fn addr(&self, _image: &str) -> SocketAddr {
        todo!("T1a")
    }

    /// `image`'s admin listener.
    #[must_use]
    pub fn admin_addr(&self, _image: &str) -> Option<SocketAddr> {
        todo!("T1a")
    }

    /// The run report so far.
    #[must_use]
    pub fn report(&self) -> &Report {
        todo!("T1a")
    }

    /// Judges the run.
    ///
    /// # Errors
    /// Never yet.
    pub fn finish(self) -> Result<Report, Unserved> {
        todo!("T1a")
    }
}

/// One image on its own thread.
pub struct PluginThread<K: Openable>(PhantomData<K>);

impl<K: Openable> PluginThread<K> {
    /// Opens `img` on a new thread.
    ///
    /// # Errors
    /// Never yet.
    pub fn open(
        _make_host: impl FnOnce() -> Host + Send + 'static,
        _img: Image<K>,
        _name: &str,
        _settings: &[u8],
    ) -> Result<Self, HostRefused> {
        todo!("T1a")
    }

    /// Runs `f` on the image's thread.
    pub fn run<R: Send + 'static>(
        &self,
        _f: impl FnOnce(&mut Opened<K>) -> R + Send + 'static,
    ) -> Option<R> {
        todo!("T1a")
    }
}
