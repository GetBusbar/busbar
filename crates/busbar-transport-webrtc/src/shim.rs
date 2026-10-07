// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SHIM: what the media stack sees in place of its own DTLS (THE DESIGN l.707-712,
//! l.756-765: DTLS runs in the host's secure layer; the framer holds no DTLS state).
//!
//! It runs no handshake, parses no record and holds no DTLS key. It only RELAYS what the host's
//! secure layer reported through the datagram lane:
//!
//! * the exported keying material (the keying-material item), handed up once, then zeroed;
//! * "connected", once the host verified the far end;
//! * plaintext the secure layer opened (the secured lane), handed up as application data;
//!
//! and takes the application data the media stack wants sealed, for the framer to route on the
//! secured lane, which the host seals. Before the host's "connected", nothing is taken for sealing
//! (the media stack retries: [`dimpl::Error::HandshakePending`]).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use str0m::crypto::dtls::{
    DtlsImplError, DtlsInstance, DtlsOutput, KeyingMaterial, ProtocolVersion, SrtpProfile,
};
use zeroize::Zeroizing;

/// The DTLS factory of [`crate::crypto::provider`]: it hands out the shim armed for the
/// association being built ([`arm`]), never a DTLS engine.
#[derive(Debug)]
pub struct Host;

/// The one factory.
pub static HOST: Host = Host;

std::thread_local! {
    static PENDING: std::cell::RefCell<Option<Shim>> = const { std::cell::RefCell::new(None) };
}

/// Arm `shim` as the one the next association built on this thread receives.
pub fn arm(shim: Shim) {
    PENDING.with(|p| *p.borrow_mut() = Some(shim));
}

/// The armed shim, taken.
pub fn take_pending() -> Option<Shim> {
    PENDING.with(|p| p.borrow_mut().take())
}

/// How far ahead the shim's timer lies: it has nothing to time.
const IDLE: Duration = Duration::from_secs(3600);

/// The relay's state, shared by the media stack's handle and the framing's.
#[derive(Debug, Default)]
pub struct Relay {
    active: Option<bool>,
    keying: Option<(Zeroizing<Vec<u8>>, SrtpProfile)>,
    connected: bool,
    connected_owed: bool,
    opened: VecDeque<Zeroizing<Vec<u8>>>,
    to_seal: VecDeque<Vec<u8>>,
    closed: bool,
    now: Option<Instant>,
}

/// One association's shim.
#[derive(Debug, Clone, Default)]
pub struct Shim(Arc<Mutex<Relay>>);

impl Shim {
    fn lock(&self) -> MutexGuard<'_, Relay> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The host's secure layer exported `material` under `profile`.
    pub fn keyed(&self, material: &[u8], profile: SrtpProfile) {
        self.lock().keying = Some((Zeroizing::new(material.to_vec()), profile));
    }

    /// The host verified the far end: the handshake is, for the media stack, connected.
    pub fn connected(&self) {
        let mut r = self.lock();
        if !r.connected {
            r.connected = true;
            r.connected_owed = true;
        }
    }

    /// Whether the host reported the far end verified.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.lock().connected
    }

    /// Plaintext the host's secure layer opened.
    pub fn opened(&self, plaintext: &[u8]) {
        self.lock()
            .opened
            .push_back(Zeroizing::new(plaintext.to_vec()));
    }

    /// The next plaintext the media stack wants sealed.
    pub fn take_to_seal(&self) -> Option<Vec<u8>> {
        self.lock().to_seal.pop_front()
    }

    /// The role the media stack settled: `Some(true)` = this end opens the handshake.
    #[must_use]
    pub fn active(&self) -> Option<bool> {
        self.lock().active
    }

    /// Whether material is still held (not yet handed to the media stack).
    #[must_use]
    pub fn holds_keying(&self) -> bool {
        self.lock().keying.is_some()
    }
}

impl DtlsInstance for Shim {
    fn set_active(&mut self, active: bool) {
        self.lock().active = Some(active);
    }

    fn handle_packet(&mut self, _packet: &[u8]) -> Result<(), DtlsImplError> {
        // The host's secure layer keeps every record: none reaches the framer.
        Ok(())
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        let mut r = self.lock();
        if let Some((material, profile)) = r.keying.take() {
            return DtlsOutput::KeyingMaterial(KeyingMaterial::new(&material), profile);
        }
        if r.connected_owed {
            r.connected_owed = false;
            return DtlsOutput::Connected;
        }
        while let Some(data) = r.opened.pop_front() {
            if let Some(dst) = buf.get_mut(..data.len()) {
                dst.copy_from_slice(&data);
                drop(r);
                return DtlsOutput::ApplicationData(&buf[..data.len()]);
            }
            // A plaintext larger than the stack's record buffer is no message it can read.
        }
        let at = r.now.unwrap_or_else(Instant::now) + IDLE;
        DtlsOutput::Timeout(at)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.lock().now = Some(now);
        Ok(())
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        let mut r = self.lock();
        if !r.connected || r.closed {
            return Err(DtlsImplError::HandshakePending);
        }
        r.to_seal.push_back(data.to_vec());
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.lock().active.unwrap_or(false)
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        None
    }

    fn is_closed(&self) -> bool {
        self.lock().closed
    }

    fn close(&mut self) -> Result<(), DtlsImplError> {
        self.lock().closed = true;
        Ok(())
    }
}
