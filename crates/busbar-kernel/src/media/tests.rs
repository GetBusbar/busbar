// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-K11: core's side of C-WEBRTC-DIAL (IF §12.13, §14). The case file's arms run end to end in
//! busbar-plugin-test (owner W1-K8A, WBS rule 10); these pin the rules core alone decides, over a fake carrier.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
use futures::executor::block_on;

use super::{resolve, DialOpening, Lines, Media, MediaCarrier, MediaLeg, MediaRendezvous};
use crate::plugin_records::RecordsDenied;

fn lines(media: &[&str], channels: &[&str]) -> Lines {
    Lines {
        media: media.iter().map(|&m| m.into()).collect(),
        channels: channels.iter().map(|&c| c.into()).collect(),
    }
}

fn pairs(list: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Reply::new();
    for (name, value) in list {
        out.put_pair(tag::PAIR, name, value.as_bytes()).unwrap();
    }
    out.as_bytes().to_vec()
}

struct Leg {
    /// An accepted leg's settled lines; `None` = the leg closed.
    caller: Option<Lines>,
    /// A dialled leg's answered lines.
    answered: Lines,
    closed: Arc<AtomicBool>,
}

impl MediaLeg for Leg {
    fn settled(&self) -> BoxFut<'_, Result<Lines, RecordsDenied>> {
        let got = self.caller.clone().ok_or(RecordsDenied::Unavailable);
        Box::pin(async move { got })
    }
    fn answer<'a>(&'a self, description: &'a str) -> BoxFut<'a, Result<Lines, RecordsDenied>> {
        assert_eq!(description, "answer-sdp");
        let got = self.answered.clone();
        Box::pin(async move { Ok(got) })
    }
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct Carrier {
    caller: Option<Lines>,
    answered: Lines,
    closed: Arc<AtomicBool>,
    dialled: Mutex<Vec<(u32, Vec<u8>)>>,
}

impl Carrier {
    fn leg(&self) -> Box<dyn MediaLeg> {
        Box::new(Leg {
            caller: self.caller.clone(),
            answered: self.answered.clone(),
            closed: Arc::clone(&self.closed),
        })
    }
}

impl MediaCarrier for Carrier {
    fn accept<'a>(
        &'a self,
        _route: u32,
        offer: &'a str,
    ) -> BoxFut<'a, Result<(Box<str>, Box<dyn MediaLeg>), RecordsDenied>> {
        assert_eq!(offer, "caller-offer");
        let leg = self.leg();
        Box::pin(async move { Ok(("caller-answer".into(), leg)) })
    }
    fn dial<'a>(
        &'a self,
        route: u32,
        opening: &'a [u8],
    ) -> BoxFut<'a, Result<(Box<str>, Box<dyn MediaLeg>), RecordsDenied>> {
        self.dialled.lock().unwrap().push((route, opening.to_vec()));
        let leg = self.leg();
        Box::pin(async move { Ok(("local-offer".into(), leg)) })
    }
}

fn media(carrier: Carrier) -> Media<Carrier> {
    Media::new(carrier)
}

/// C-WEBRTC-DIAL (a), core part: the accepted caller leg (one audio line, channel `oai-events`) gives exactly
/// `media`=`audio`, `channel`=`oai-events`, and the dial hands those bytes on unchanged as `ConnInfo.head`.
#[test]
fn accepted_leg_opening_is_its_lines_then_channels_and_dials_unchanged() {
    let core = media(Carrier {
        caller: Some(lines(&["audio"], &["oai-events"])),
        ..Carrier::default()
    });
    let (answer, caller) = block_on(core.accept(3, "caller-offer")).unwrap();
    assert_eq!(&*answer, "caller-answer");
    let opening = block_on(caller.opening()).unwrap();
    let read: Vec<(String, Vec<u8>)> = Records::new(&opening)
        .map(|r| {
            let r = r.unwrap();
            assert_eq!(r.tag, tag::PAIR);
            let (name, value) = r.pair().unwrap();
            (name.to_owned(), value.to_vec())
        })
        .collect();
    assert_eq!(
        read,
        [
            ("media".to_owned(), b"audio".to_vec()),
            ("channel".to_owned(), b"oai-events".to_vec())
        ]
    );
    let (offer, _upstream) = block_on(core.dial(9, &opening)).unwrap();
    assert_eq!(&*offer, "local-offer");
    assert_eq!(
        *core.carrier.dialled.lock().unwrap(),
        [(9, opening.to_vec())]
    );
}

/// `opening` is a caller leg's answer only: a closed leg or one with nothing settled is `Unavailable`, a
/// dialled bridge `Invalid`; and `remote` is a dialled bridge's only.
#[test]
fn each_bridge_answers_only_its_own_side() {
    let closed = media(Carrier::default());
    let (_, bridge) = block_on(closed.accept(1, "caller-offer")).unwrap();
    assert_eq!(block_on(bridge.opening()), Err(RecordsDenied::Unavailable));

    let empty = media(Carrier {
        caller: Some(Lines::default()),
        ..Carrier::default()
    });
    let (_, mut bridge) = block_on(empty.accept(1, "caller-offer")).unwrap();
    assert_eq!(block_on(bridge.opening()), Err(RecordsDenied::Unavailable));
    assert_eq!(
        block_on(bridge.remote("answer-sdp")),
        Err(RecordsDenied::Invalid)
    );

    let (_, dialled) = block_on(empty.dial(1, &pairs(&[("media", "audio")]))).unwrap();
    assert_eq!(block_on(dialled.opening()), Err(RecordsDenied::Invalid));
}

/// C-WEBRTC-DIAL (b), core part: an answered leg that does not mirror the opening closes the dialled session,
/// `remote` is `Invalid`, and the refusal carries `mirrored`'s text (count, kind, or a missing channel).
#[test]
fn a_non_mirroring_answer_closes_the_dial_with_mirrored_text() {
    let opening = pairs(&[("media", "audio"), ("channel", "oai-events")]);
    for (answered, text) in [
        (
            lines(&["video"], &["oai-events"]),
            "line 0 is `audio` on the caller's leg and `video` upstream",
        ),
        (
            lines(&["audio", "audio"], &["oai-events"]),
            "the upstream leg carries 2 line(s), the caller's 1",
        ),
        (
            lines(&["audio"], &[]),
            "the upstream leg carries no channel `oai-events`",
        ),
    ] {
        let core = media(Carrier {
            answered,
            ..Carrier::default()
        });
        let (_, mut bridge) = block_on(core.dial(2, &opening)).unwrap();
        assert_eq!(
            block_on(bridge.remote("answer-sdp")),
            Err(RecordsDenied::Invalid)
        );
        assert!(core.carrier.closed.load(Ordering::SeqCst), "{text}");
        assert_eq!(bridge.refusal(), Some(text));
    }
}

/// C-WEBRTC-DIAL (c), core part: a mirroring answer (extra channels the far end opened are its own) opens the
/// bridge and nothing is closed.
#[test]
fn a_mirroring_answer_opens_the_bridge() {
    let core = media(Carrier {
        answered: lines(&["audio"], &["oai-events", "far-own"]),
        ..Carrier::default()
    });
    let opening = pairs(&[("media", "audio"), ("channel", "oai-events")]);
    let (_, mut bridge) = block_on(core.dial(2, &opening)).unwrap();
    assert_eq!(block_on(bridge.remote("answer-sdp")), Ok(()));
    assert!(!core.carrier.closed.load(Ordering::SeqCst));
    assert_eq!(bridge.refusal(), None);
}

/// C-WEBRTC-DIAL (d), core part: an opening that is empty, names anything but `media`/`channel`, puts a
/// `channel` before a `media`, carries an empty or multi-line value, or holds a record that is no PAIR is
/// `Invalid`, and the carrier is never reached.
#[test]
fn a_dial_with_an_opening_it_cannot_state_is_never_dialled() {
    let mut bad = vec![
        Vec::new(),
        pairs(&[("channel", "oai-events"), ("media", "audio")]),
        pairs(&[("mirror", "1")]),
        pairs(&[("media", "")]),
        pairs(&[("media", "audio\r\nm=video")]),
        pairs(&[("media", "audio video")]),
        pairs(&[("channel", "a\nb")]),
        vec![0xff; 3],
    ];
    let mut fact = Reply::new();
    fact.put(tag::FACT_TEXT, b"media").unwrap();
    bad.push(fact.as_bytes().to_vec());
    let core = media(Carrier::default());
    for opening in &bad {
        assert!(
            matches!(block_on(core.dial(4, opening)), Err(RecordsDenied::Invalid)),
            "{opening:?}"
        );
    }
    assert!(core.carrier.dialled.lock().unwrap().is_empty());
    assert_eq!(
        Lines::read(&pairs(&[("channel", "only-a-channel")])),
        Ok(lines(&[], &["only-a-channel"]))
    );
}

/// The UP_NEW(CARRIER_RTC) PAIR* resolution K8 runs (§12.13): one decimal `mirror` alone, or valid lines;
/// anything else is the FAULT.
#[test]
fn up_new_pairs_resolve_to_one_mirror_or_valid_lines() {
    fn p(list: &[(&'static str, &'static str)]) -> Result<DialOpening, RecordsDenied> {
        resolve(list.iter().map(|&(n, v)| (n, v.as_bytes())))
    }
    assert_eq!(p(&[("mirror", "1")]), Ok(DialOpening::Mirror(1)));
    assert_eq!(
        p(&[("media", "audio"), ("channel", "oai-events")]),
        Ok(DialOpening::Lines(lines(&["audio"], &["oai-events"])))
    );
    let bad: [&[(&str, &str)]; 10] = [
        &[],
        &[("mirror", "")],
        &[("mirror", "+1")],
        &[("mirror", "one")],
        &[("mirror", "99999999999999999999999")],
        &[("mirror", "1"), ("mirror", "2")],
        &[("mirror", "1"), ("media", "audio")],
        &[("media", "audio"), ("mirror", "1")],
        &[("channel", "c"), ("media", "audio")],
        &[("label", "x")],
    ];
    for bad in bad {
        assert_eq!(p(bad), Err(RecordsDenied::Invalid), "{bad:?}");
    }
}
