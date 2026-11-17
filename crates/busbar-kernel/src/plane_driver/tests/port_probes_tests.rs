// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6 FB_PROBES (PLANE-DRIVER slice 5 leftover): the probe service's target over the plane port. The plane
//! is scripted; the far end and the breaker are fakes.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_plugin_abi::plane::{ATT_DECLINE, F_PROBE_OK, P_END, P_HEAD};
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_ports::{FactRef, PortError};

use super::{PortProbes, ProbeFar};
use crate::plane_driver::port_session::{Calls, Effects, UpExchange};
use crate::plane_driver::port_upstream::{Candidate, ProbeOutcome, SendFailed, UpReply, UpSend};
use crate::probe::ProbeTarget;

struct Live;

/// A plane whose probe answer is an exchange, or a decline, and whose `end` says whether the member is well.
struct Plane {
    decline: bool,
    well: bool,
    seen: Mutex<Vec<(u32, String, String)>>,
}

fn nope() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

impl Calls for Plane {
    type Session = Live;

    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Live, PortError> {
        Err(nope())
    }

    fn piece(
        &self,
        _: &mut Live,
        from: u32,
        _: u32,
        flags: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        assert_eq!(from, busbar_plugin_abi::plane::FROM_UPSTREAM);
        assert!(flags == P_HEAD || flags == P_END);
        Ok(())
    }

    fn rewrite(
        &self,
        _: &mut Live,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }

    fn end(&self, _: Live, sink: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        sink(PlaneOut::Fact(F_PROBE_OK, FactRef::U(u64::from(self.well))));
        Ok(())
    }

    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(nope())
    }

    fn upstream(
        &self,
        _: &mut Live,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(nope())
    }

    fn probe(
        &self,
        t: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Live, PortError> {
        self.seen
            .lock()
            .unwrap()
            .push((t.attempt, t.upstream.into(), t.model.into()));
        if self.decline {
            sink(PlaneOut::Attempt {
                verdict: ATT_DECLINE,
                class: 0,
                retry_after_s: 0,
                reason: "",
            });
        } else {
            sink(PlaneOut::UpMethod("GET"));
            sink(PlaneOut::UpPath("/health"));
            sink(PlaneOut::UpEnd);
        }
        Ok(Live)
    }
}

struct Quiet;

impl Effects for Quiet {
    fn emit(&self, _: u64, _: &[u8]) {}
}

struct Far;

impl UpSend for Far {
    fn send(&mut self, _: &Candidate, _: &UpExchange) -> Result<UpReply, SendFailed> {
        Ok(UpReply {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        })
    }
}

#[derive(Default)]
struct Members {
    suppressed: Vec<usize>,
    reported: Mutex<Vec<(usize, ProbeOutcome)>>,
    no_sender: bool,
}

impl ProbeFar for Members {
    fn suppressing(&self, member: usize) -> bool {
        self.suppressed.contains(&member)
    }

    fn candidate(&self, member: usize) -> Option<Candidate> {
        (member < 2).then(|| Candidate {
            pool: "pool".into(),
            qualified_member: "fixture-member".into(),
            identity: crate::plane_driver::port_upstream::TargetIdentity::Registration,
            upstream: format!("m{member}").into(),
            provider: "{}".into(),
            base_path: "/v1".into(),
            flags: 0,
            params: Vec::new(),
        })
    }

    fn sender(&self, _: usize, _: Duration) -> Option<Box<dyn UpSend + Send>> {
        (!self.no_sender).then(|| Box::new(Far) as Box<dyn UpSend + Send>)
    }

    fn reported(&self, member: usize, outcome: ProbeOutcome) {
        self.reported.lock().unwrap().push((member, outcome));
    }
}

fn target(plane: Plane, far: Members) -> (PortProbes<Plane, Members>, Arc<Plane>, Arc<Members>) {
    let plane = Arc::new(plane);
    let far = Arc::new(far);
    (
        PortProbes::new(
            Arc::clone(&plane),
            Arc::clone(&far),
            "openai".into(),
            "probe-model".into(),
            Arc::new(Quiet),
        ),
        plane,
        far,
    )
}

fn plane(decline: bool, well: bool) -> Plane {
    Plane {
        decline,
        well,
        seen: Mutex::default(),
    }
}

#[tokio::test]
async fn a_probe_asks_the_plane_about_that_member_and_reports_what_it_found() {
    let (probes, plane, far) = target(plane(false, true), Members::default());
    probes.probe(1, Duration::from_secs(1)).await;
    assert_eq!(
        *plane.seen.lock().unwrap(),
        vec![(1, "m1".to_owned(), "probe-model".to_owned())]
    );
    assert_eq!(
        *far.reported.lock().unwrap(),
        vec![(1, ProbeOutcome::Healthy)]
    );

    let (probes, _, far) = target(plane_unwell(), Members::default());
    probes.probe(0, Duration::from_secs(1)).await;
    assert_eq!(
        *far.reported.lock().unwrap(),
        vec![(0, ProbeOutcome::Unhealthy)]
    );
}

fn plane_unwell() -> Plane {
    plane(false, false)
}

#[tokio::test]
async fn a_member_the_plane_declines_to_probe_reports_nothing() {
    let (probes, _, far) = target(plane(true, false), Members::default());
    probes.probe(0, Duration::from_secs(1)).await;
    assert!(far.reported.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_unknown_member_or_one_with_no_way_to_reach_it_is_not_probed() {
    let (probes, plane, far) = target(plane(false, true), Members::default());
    probes.probe(9, Duration::from_secs(1)).await;
    assert!(plane.seen.lock().unwrap().is_empty());
    assert!(far.reported.lock().unwrap().is_empty());

    let (probes, plane, _) = target(
        plane_ok(),
        Members {
            no_sender: true,
            ..Members::default()
        },
    );
    probes.probe(0, Duration::from_secs(1)).await;
    assert!(
        plane.seen.lock().unwrap().is_empty(),
        "no plane call without a far end"
    );
}

fn plane_ok() -> Plane {
    plane(false, true)
}

#[test]
fn suppression_is_the_breakers_word() {
    let (probes, _, _) = target(
        plane(false, true),
        Members {
            suppressed: vec![1],
            ..Members::default()
        },
    );
    assert!(probes.suppressing(1));
    assert!(!probes.suppressing(0));
}
